#include "Serve.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <arpa/inet.h>
#include <httplib.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <regex>
#include <thread>

#include "../config/GlobalConfig.h"
#include "../core/UIManager.h"
#include "../core/base64.h"
#include "../core/terminal_ui.h"
#include "../vault/Crypto.h"
#include "../vault/EspStore.h"
#include "../vault/LocalFileStore.h"
#include "../vault/OpenSsl.h"
#include "../vault/Pairing.h"
#include "../vault/PinUnlock.h"
#include "../vault/VaultService.h"

namespace {
namespace fs = std::filesystem;
using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;
using httplib::Request;
using httplib::Response;

using Bignum = Owned<BIGNUM, BN_free>;

void writePrivate(const std::string& path, const std::string& content) {  // mode 600, atomically
    writePrivateTmp(path, content);
    fs::rename(path + ".tmp", path);
}

Pkey readKey(const std::string& pem) {
    Bio b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    return Pkey(PEM_read_bio_PrivateKey(b.get(), nullptr, nullptr, nullptr));
}

// Valid 2025-2049 like the board's certs; self-signed without an issuer.
Cert makeCert(EVP_PKEY* key,
              const std::string& cn,
              X509* issuer,
              EVP_PKEY* issuerKey,
              const std::vector<std::pair<int, std::string>>& exts) {
    Cert x(X509_new());
    unsigned char serial[16];
    RAND_bytes(serial, sizeof serial);
    serial[0] &= 0x7f;  // positive
    Bignum bn(BN_bin2bn(serial, sizeof serial, nullptr));
    bool ok = x && bn && X509_set_version(x.get(), 2) && BN_to_ASN1_INTEGER(bn.get(), X509_get_serialNumber(x.get())) &&
              ASN1_TIME_set_string_X509(X509_getm_notBefore(x.get()), "20250101000000Z") &&
              ASN1_TIME_set_string_X509(X509_getm_notAfter(x.get()), "20491231235959Z") &&
              X509_set_pubkey(x.get(), key) &&
              X509_NAME_add_entry_by_txt(X509_get_subject_name(x.get()),
                                         "CN",
                                         MBSTRING_UTF8,
                                         reinterpret_cast<const unsigned char*>(cn.c_str()),
                                         -1,
                                         -1,
                                         0) &&
              X509_set_issuer_name(x.get(), X509_get_subject_name(issuer ? issuer : x.get()));
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer ? issuer : x.get(), x.get(), nullptr, nullptr, 0);
    for (const auto& [nid, value] : exts) {
        X509_EXTENSION* e = ok ? X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str()) : nullptr;
        ok = e && X509_add_ext(x.get(), e, -1);
        X509_EXTENSION_free(e);
    }
    if (!ok || !X509_sign(x.get(), issuerKey, EVP_sha256()))
        throw std::runtime_error("OpenSSL: couldn't make a cert");
    return x;
}

// This host's TLS identity and device CA (PROTOCOL.md §7, §10), made on first start in configDir()/serve/, mode
// 600: the board's /server.pem and /ca.pem. Its id (§8) is the SHA-256 of the server cert.
struct Identity {
    std::string serverPem, serverKey, caPem;  // paths, for the TLS servers
    Cert ca;
    Pkey caKey;
    std::string id;
};

Identity loadIdentity() {
    const std::string dir = ConfigManager::configDir() + "/serve";
    Identity me{dir + "/server.pem", dir + "/server.key", dir + "/ca.pem", nullptr, nullptr, ""};
    const std::string caKeyPath = dir + "/ca.key";
    // A self-signed key and cert, made once
    auto ensure = [](const std::string& keyPath, const std::string& certPath, const std::string& cn,
                     const std::vector<std::pair<int, std::string>>& exts) {
        if (fs::exists(keyPath) && fs::exists(certPath)) return;
        Pkey k(EVP_EC_gen("P-256"));
        Cert c = makeCert(k.get(), cn, nullptr, k.get(), exts);
        Bio key(BIO_new(BIO_s_mem())), cert(BIO_new(BIO_s_mem()));
        PEM_write_bio_PrivateKey(key.get(), k.get(), nullptr, nullptr, 0, nullptr, nullptr);
        PEM_write_bio_X509(cert.get(), c.get());
        writePrivate(keyPath, bioString(key.get()));
        writePrivate(certPath, bioString(cert.get()));
    };
    ensure(me.serverKey, me.serverPem, "pwvault.local",  // like the board's
           {{NID_basic_constraints, "CA:TRUE"}, {NID_subject_alt_name, "DNS:pwvault.local"}});
    ensure(caKeyPath, me.caPem, "pwvault device CA",
           {{NID_basic_constraints, "critical,CA:TRUE,pathlen:0"}, {NID_key_usage, "critical,keyCertSign"}});
    me.ca = readCert(readFile(me.caPem));
    me.caKey = readKey(readFile(caKeyPath));
    me.id = certFingerprint(readFile(me.serverPem));
    if (!me.ca || !me.caKey || me.id.empty())
        throw std::runtime_error("unreadable keys in " + dir);
    return me;
}

// The terminal stands in for the board's BOOT button: what needs someone at the host waits here for y/n.
class Console {
   public:
    void say(const std::string& line) {
        std::lock_guard<std::mutex> l(m_);
        std::cout << "\r" << line << std::endl;
        if (!asks_.empty())
            prompt();
    }
    // Asks the person at the host; `done` gets the answer, or false after `seconds` without one.
    // `key` names it for reword().
    void ask(const std::string& question, int seconds, std::function<void(bool)> done, const std::string& key = "") {
        std::unique_lock<std::mutex> l(m_);
        if (closed_) {  // stopping: a question now would keep stop() waiting for its answer
            l.unlock();
            return done(false);
        }
        asks_.push_back({question, Clock::now() + std::chrono::seconds(seconds), std::move(done), key});
        if (asks_.size() == 1)
            prompt();
    }
    // A pending question's subject changed (a newer revoke request): what's asked is what a y will do.
    void reword(const std::string& key, const std::string& question) {
        std::lock_guard<std::mutex> l(m_);
        for (size_t i = 0; i < asks_.size(); i++)
            if (asks_[i].key == key) {
                asks_[i].question = question;
                if (i == 0) prompt();
            }
    }
    bool askAndWait(const std::string& question, int seconds) {
        auto answer = std::make_shared<std::promise<bool>>();
        auto got = answer->get_future();
        ask(question, seconds, [answer](bool ok) { answer->set_value(ok); });
        return got.get();  // the input loop answers or expires every question
    }
    // A line from the input loop answers the oldest question, if there is one.
    bool answer(const std::string& line) {
        std::function<void(bool)> done;
        {
            std::lock_guard<std::mutex> l(m_);
            if (asks_.empty())
                return false;
            done = std::move(asks_.front().done);
            asks_.pop_front();
            if (!asks_.empty())
                prompt();
        }
        done(line == "y" || line == "yes");
        return true;
    }
    void expire(bool all = false) {
        std::vector<std::function<void(bool)>> late;
        {
            std::lock_guard<std::mutex> l(m_);
            while (!asks_.empty() && (all || asks_.front().until < Clock::now())) {
                late.push_back(std::move(asks_.front().done));
                asks_.pop_front();
                std::cout << "no answer: refused" << std::endl;
                if (!asks_.empty())
                    prompt();
            }
        }
        for (auto& done : late)
            done(false);
    }

    // Closed before the servers stop, so no request can start waiting for an answer that nobody will give;
    // open while serving.
    void setOpen(bool open) {
        {
            std::lock_guard<std::mutex> l(m_);
            closed_ = !open;
        }
        if (!open) expire(true);
    }

   private:
    void prompt() {
        std::cout << term::bold(asks_.front().question) << " [y/N] " << std::flush;
    }
    struct Ask {
        std::string question;
        Clock::time_point until;
        std::function<void(bool)> done;
        std::string key;
    };
    std::mutex m_;
    bool closed_ = false;
    std::deque<Ask> asks_;
};

void reply(Response& res, int status, const Json& body) {
    res.status = status;
    res.set_content(body.dump(), "application/json");
}

void refuse(Response& res, int status, const std::string& error) {
    reply(res, status, {{"error", error}});
}

// For the pairing QR: the address this computer's traffic leaves from, i.e. the one its network can reach. Asking the
// kernel which source it would use towards a public address sends nothing. Without a route (offline), the first
// IPv4 interface that's up and not loopback, which may be a VM bridge or a VPN: --address says it outright.
std::string localAddress() {
    std::string out;
    if (int s = socket(AF_INET, SOCK_DGRAM, 0); s >= 0) {
        sockaddr_in to{}, from{};
        socklen_t len = sizeof from;
        to.sin_family = AF_INET;
        to.sin_port = htons(53);
        inet_pton(AF_INET, "192.0.2.1", &to.sin_addr);  // TEST-NET-1: routed like any public address, never used
        char buf[INET_ADDRSTRLEN] = "";
        if (connect(s, reinterpret_cast<sockaddr*>(&to), sizeof to) == 0 &&
            getsockname(s, reinterpret_cast<sockaddr*>(&from), &len) == 0 &&
            inet_ntop(AF_INET, &from.sin_addr, buf, sizeof buf) && std::string(buf) != "0.0.0.0")
            out = buf;
        close(s);
        if (!out.empty()) return out;
    }
    ifaddrs* all = nullptr;
    if (getifaddrs(&all) != 0)
        return out;
    for (ifaddrs* a = all; a && out.empty(); a = a->ifa_next)
        if (a->ifa_addr && a->ifa_addr->sa_family == AF_INET && (a->ifa_flags & IFF_UP) &&
            !(a->ifa_flags & IFF_LOOPBACK)) {
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(a->ifa_addr)->sin_addr, buf, sizeof buf);
            out = buf;
        }
    freeifaddrs(all);
    return out;
}

// The host: §7's API on `port` (mutual TLS, devices this host's CA issued and devices.json lists) and §9's
// pairing on port + 1, over this computer's own vault file.
class Host {
   public:
    Host(Identity me, HostRole role, int port, std::string address, const std::string& vaultPath, Console& console)
        : me_(std::move(me)), role_(role), port_(port), address_(std::move(address)), vaultPath_(vaultPath),
          store_(vaultPath), console_(console) {
        Json j = Json::parse(readFile(devicesPath()), nullptr, false);
        if (j.is_object())
            for (auto& [name, fp] : j.items())
                devices_[name] = fp.get<std::string>();
    }
    ~Host() {
        stop();
    }

    [[nodiscard]] bool serving() const {
        return api_ != nullptr;
    }

    void start() {
        api_ = std::make_unique<httplib::SSLServer>(me_.serverPem.c_str(), me_.serverKey.c_str(), me_.caPem.c_str());
        pair_ = std::make_unique<httplib::SSLServer>(me_.serverPem.c_str(), me_.serverKey.c_str());
        if (!api_->is_valid() || !pair_->is_valid())
            throw std::runtime_error("couldn't load the TLS keys");
        routes();
        if (!api_->bind_to_port("0.0.0.0", port_) || !pair_->bind_to_port("0.0.0.0", port_ + 1)) {
            api_.reset(), pair_.reset();
            throw std::runtime_error("port " + std::to_string(port_) + " or " + std::to_string(port_ + 1) +
                                     " is in use");
        }
        threads_.emplace_back([this] { api_->listen_after_bind(); });
        threads_.emplace_back([this] { pair_->listen_after_bind(); });
    }

    void stop() {
        if (!serving())
            return;
        api_->stop();
        pair_->stop();
        for (auto& t : threads_)
            t.join();
        threads_.clear();
        api_.reset(), pair_.reset();
        std::lock_guard<std::mutex> l(pm_);
        code_.clear();
    }

    // §9: like a BOOT press. Returns the code, the QR text and the seconds left.
    Json openPairing(const std::string& by) {
        std::lock_guard<std::mutex> l(pm_);
        const std::string address = address_.empty() ? localAddress() : address_;
        if (code_.empty() || Clock::now() > until_) {
            static const char kAlphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";  // Crockford base32: 32 divides 256
            unsigned char raw[16];
            RAND_bytes(raw, sizeof raw);
            code_.clear();
            for (unsigned char b : raw)
                code_ += kAlphabet[b % 32];
            until_ = Clock::now() + std::chrono::minutes(2);
            std::cout << "\r\n"
                      << term::qrText("PWVAULT:" + address + ":" + code_ + ":" + std::to_string(port_))
                      << "Pairing is open for 2 minutes" << (by.empty() ? "" : " (asked by " + by + ")") << ". Code "
                      << term::bold(code_.substr(0, 4) + "-" + code_.substr(4, 4) + "-" + code_.substr(8, 4) + "-" +
                                    code_.substr(12))
                      << ", address " << address << ":" << port_ << std::endl;
        }
        const auto left = std::chrono::duration_cast<std::chrono::seconds>(until_ - Clock::now()).count();
        return {{"code", code_},
                {"qr", "PWVAULT:" + address + ":" + code_ + ":" + std::to_string(port_)},
                {"seconds", left}};
    }

    void listDevices() {
        std::lock_guard<std::mutex> l(dm_);
        if (devices_.empty())
            console_.say("No devices yet. Type p to open pairing.");
        for (const auto& [name, fp] : devices_)
            console_.say("  " + name +
                         (seen_.count(name)
                              ? "  last seen " + std::to_string(std::time(nullptr) - seen_[name]) + " s ago"
                              : ""));
    }

    bool revoke(const std::string& name) {
        std::lock_guard<std::mutex> l(dm_);
        if (!devices_.erase(name))
            return false;
        saveDevices();
        return true;
    }

   private:
    std::string devicesPath() const {
        return fs::path(me_.caPem).parent_path().string() + "/devices.json";
    }
    void saveDevices() {  // under dm_
        writePrivate(devicesPath(), Json(devices_).dump());
    }

    // §9 step 4: the CSR's key, as CN=name, for client auth only.
    std::string issue(const std::string& name, const std::string& csrDer) {
        auto* p = reinterpret_cast<const unsigned char*>(csrDer.data());
        Req req(d2i_X509_REQ(nullptr, &p, static_cast<long>(csrDer.size())));
        Pkey key(req ? X509_REQ_get_pubkey(req.get()) : nullptr);
        if (!key || X509_REQ_verify(req.get(), key.get()) != 1)
            throw std::invalid_argument("bad csr");
        Cert c = makeCert(key.get(),
                          name,
                          me_.ca.get(),
                          me_.caKey.get(),
                          {{NID_key_usage, "critical,digitalSignature"}, {NID_ext_key_usage, "clientAuth"}});
        return der(c.get());
    }

    // §7: the device is the cert's CN, and only if devices.json maps it to exactly this cert.
    std::optional<std::string> authorize(const Request& req, Response& res) {
        Cert peer(req.ssl ? SSL_get1_peer_certificate(req.ssl) : nullptr);
        char cn[64] = "";
        if (peer)
            X509_NAME_get_text_by_NID(X509_get_subject_name(peer.get()), NID_commonName, cn, sizeof cn);
        std::lock_guard<std::mutex> l(dm_);
        auto it = devices_.find(cn);
        if (!peer || it == devices_.end() || it->second != vaultcrypto::sha256Hex(der(peer.get()))) {
            res.set_header("Connection", "close");
            refuse(res, 403, "device revoked");
            return std::nullopt;
        }
        seen_[cn] = std::time(nullptr);
        return std::string(cn);
    }

    using Handler = std::function<void(const std::string& who, const Request&, Response&)>;
    httplib::Server::Handler api(Handler h) {  // authorized, one store call at a time (like the board)
        return [this, h](const Request& req, Response& res) {
            if (auto who = authorize(req, res)) {
                std::lock_guard<std::mutex> l(sm_);
                h(*who, req, res);
            }
        };
    }

    uint64_t storeSeq() {
        return store_.changesAfter(UINT64_MAX).seq;
    }

    void routes() {
        api_->set_payload_max_length(16 * 1024);  // §7: 413 above that
        api_->set_keep_alive_max_count(1000);     // clients keep one connection open
        api_->set_keep_alive_timeout(60);
        api_->set_exception_handler(
            [](const Request&, Response& res, std::exception_ptr) { refuse(res, 400, "bad request"); });

        api_->Get("/meta", api([this](auto&, auto&, Response& res) {
                      auto m = store_.getMeta();
                      m ? reply(res, 200, Json(*m)) : refuse(res, 404, "no vault yet");
                  }));
        api_->Put("/meta", api([this](const std::string& who, const Request& req, Response& res) {
                      Json j = Json::parse(req.body);
                      VaultMeta m = j.at("meta").get<VaultMeta>();
                      if (!store_.putMeta(m, j.at("if_rev").get<int>()))
                          return refuse(res, 409, "rev changed");
                      console_.say("[" + who + "] vault key updated (rev " + std::to_string(m.rev) + ")");
                      reply(res, 200, {{"ok", true}});
                  }));
        api_->Get("/entries", api([this](auto&, const Request& req, Response& res) {
                      auto c =
                          store_.changesAfter(req.has_param("after") ? std::stoull(req.get_param_value("after")) : 0);
                      reply(res, 200, {{"entries", c.entries}, {"seq", c.seq}});
                  }));
        api_->Post("/entries", api([this](const std::string& who, const Request& req, Response& res) {
                       static const std::regex kId(
                           "[0-9a-f]{32}");  // it becomes a key in the file, like a file name on the board
                       Json j = Json::parse(req.body, nullptr, false);
                       const Json* e = j.is_object() && j.contains("entries") ? &j["entries"] : nullptr;
                       auto valid = [](const Json& r) {
                           return r.is_object() && r.contains("id") && r["id"].is_string() &&
                                  std::regex_match(r["id"].get<std::string>(), kId) && r.contains("updated") &&
                                  r["updated"].is_number_integer() && r.contains("deleted") &&
                                  r["deleted"].is_boolean() && r.contains("alg") && r["alg"].is_string() &&
                                  r.contains("data") && r["data"].is_string();
                       };
                       if (!e || !e->is_array() || e->size() > 32 || !std::all_of(e->begin(), e->end(), valid))
                           return refuse(res, 400, "bad entry record");  // then none is written
                       const uint64_t before = storeSeq();
                       store_.putEntries(e->get<std::vector<EntryRecord>>());
                       const uint64_t after = storeSeq();
                       if (after > before)
                           console_.say("[" + who + "] synced " + std::to_string(after - before) + " change(s)");
                       reply(res, 200, {{"seq", after}});
                   }));
        api_->Post(
            "/access", api([this](const std::string& who, const Request& req, Response& res) {
                Json j = Json::parse(req.body, nullptr, false);  // display-only, like the board's OLED hint
                if (j.is_object())
                    console_.say("[" + who + "] read " + j.value("platform", "?") + " / " + j.value("username", "?"));
                reply(res, 200, {{"ok", true}});
            }));
        api_->Get("/devices", api([this](const std::string& who, auto&, Response& res) {
                      Json list = Json::array();
                      {
                          std::lock_guard<std::mutex> l(dm_);
                          for (const auto& [name, fp] : devices_)
                              list.push_back({{"name", name}, {"seen", seen_.count(name) ? seen_[name] : 0}});
                      }
                      std::error_code noFile, noSpace;  // no vault.json yet on a new host: 0 used
                      const uint64_t used = fs::file_size(vaultPath_, noFile),
                                     free = fs::space(fs::path(vaultPath_).parent_path(), noSpace).available;
                      reply(res,
                            200,
                            {{"devices", list},
                             {"you", who},
                             {"role", hostRoleName(role_)},
                             {"storage",
                              {{"used", noFile ? 0 : used},
                               {"total", (noFile ? 0 : used) + (noSpace ? 0 : free)},
                               {"records", store_.changesAfter(0).entries.size()}}}});
                  }));
        api_->Delete(R"(/devices/([a-z0-9-]{1,20}))",
                     api([this](const std::string& who, const Request& req, Response& res) {
                         const std::string name = req.matches[1];
                         {
                             std::lock_guard<std::mutex> l(dm_);
                             if (!devices_.count(name))
                                 return refuse(res, 404, "no such device");
                         }
                         // §10: only a request, which someone at the host performs; a newer one replaces it
                         bool ask;
                         {
                             std::lock_guard<std::mutex> l(dm_);
                             ask = revokeName_.empty();
                             revokeName_ = name;
                             revokeBy_ = who;
                         }
                         const std::string question = "Revoke '" + name + "' (asked by " + who + ")?";
                         if (!ask) {
                             std::cout << "\r(a newer revoke request replaces the pending one)\n";
                             console_.reword("revoke", question);
                         } else {
                             console_.ask(question, 60, [this](bool yes) {
                                 std::string target;
                                 {
                                     std::lock_guard<std::mutex> l(dm_);
                                     std::swap(target, revokeName_);
                                     revokeBy_.clear();
                                 }
                                 console_.say(yes && revoke(target) ? "[" + target + "] revoked" : "kept " + target);
                             }, "revoke");
                         }
                         reply(res, 202, {{"pending", true}});
                     }));
        api_->Post("/pair/open",
                   api([this](const std::string& who, auto&, Response& res) { reply(res, 200, openPairing(who)); }));
        auto noPin = [](const Request&, Response& res) { refuse(res, 404, "PIN unlock needs a dedicated host"); };
        api_->Put("/pin", noPin);  // §11: PINs only on dedicated hosts
        api_->Post("/pin", noPin);

        pair_->set_payload_max_length(16 * 1024);
        pair_->set_exception_handler(
            [](const Request&, Response& res, std::exception_ptr) { refuse(res, 400, "bad request"); });
        pair_->Post("/pair", [this](const Request& req, Response& res) {
            std::string code;
            {
                std::lock_guard<std::mutex> l(pm_);
                if (code_.empty() || Clock::now() > until_)
                    return refuse(res, 403, "pairing isn't open: open it on the host");
                code = code_;
                code_.clear();  // one request per pairing session, right or wrong
            }
            Json j = Json::parse(req.body);
            const std::string name = j.value("name", ""), csr = j.value("csr", ""), mac = j.value("mac", "");
            auto hmac = [&](const std::string& msg) { return vaultcrypto::toHex(vaultcrypto::hmacSha256(code, msg)); };
            const std::string want = hmac("pwvault-pair-req\n" + me_.id + "\n" + name + "\n" + csr);
            if (mac.size() != want.size() || CRYPTO_memcmp(mac.data(), want.data(), want.size()) != 0) {
                console_.say("Pairing refused: wrong code. Pairing is closed; type p to open it again.");
                return refuse(res, 403, "wrong code (or someone is intercepting)");
            }
            if (!validDeviceName(name))
                return refuse(res, 400, "name: 1-20 chars of a-z 0-9 -");
            if (!console_.askAndWait("Pair '" + name + "' with this host?", 60))
                return refuse(res, 403, "not approved on the host");
            std::string cert;
            try {
                cert = issue(name, base64::decode(csr));
            } catch (const std::exception&) {
                return refuse(res, 400, "bad csr");
            }
            {
                std::lock_guard<std::mutex> l(dm_);
                devices_[name] = vaultcrypto::sha256Hex(cert);  // re-pairing a name replaces its cert
                saveDevices();
            }
            console_.say("[" + name + "] paired");
            const std::string certB64 = base64::encode(cert);
            reply(res, 200, {{"cert", certB64}, {"mac", hmac("pwvault-pair-resp\n" + me_.id + "\n" + certB64)}});
        });
    }

    Identity me_;
    HostRole role_;
    int port_;
    std::string address_;  // --address, for the pairing QR; "" = this computer's route address
    std::string vaultPath_;
    LocalFileStore store_;
    Console& console_;
    std::unique_ptr<httplib::SSLServer> api_, pair_;
    std::vector<std::thread> threads_;
    std::mutex sm_;                               // store
    std::mutex dm_;                               // devices_, seen_
    std::map<std::string, std::string> devices_;  // name -> SHA-256 of its one valid cert
    std::map<std::string, std::time_t> seen_;     // name -> last request
    std::mutex pm_;                               // code_, until_
    std::string code_;                            // "" = pairing closed
    std::string revokeName_, revokeBy_;           // §10: the one pending revoke request (under dm_); "" = none
    Clock::time_point until_{};
};

}  // namespace

int runServe(int argc, char** argv) {
    HostRole role = HostRole::Peer;
    int port = 8443;
    std::string address;  // for the pairing QR
    for (int i = 2; i < argc; i++) {
        const std::string a = argv[i];
        if (a == "--role" && i + 1 < argc &&
            (std::string(argv[i + 1]) == "server" || std::string(argv[i + 1]) == "peer")) {
            role = hostRoleOf(argv[++i]);
        } else if (a == "--port" && i + 1 < argc && std::atoi(argv[i + 1]) > 0 && std::atoi(argv[i + 1]) < 65535) {
            port = std::atoi(argv[++i]);
        } else if (a == "--address" && i + 1 < argc) {
            address = argv[++i];
        } else {
            std::cerr << "Usage: " << argv[0] << " --serve [--role server|peer] [--port N] [--address IP]\n"
                      << "  server: an always-on machine (a Raspberry Pi); peer (default): a computer someone uses.\n"
                      << "  Pairing is on port N+1. dedicated is only for single-purpose hardware, like the board.\n"
                      << "  --address: the one to show devices in the pairing QR (default: this computer's route).\n";
            return 2;
        }
    }
    std::signal(SIGPIPE, SIG_IGN);  // a client that hangs up mid-reply must not end the host
    ConfigManager& config = ConfigManager::getInstance();
    config.loadConfig();
    const AppConfig& c = config.getConfig();
    if (!c.localCopy) {
        std::cerr << "Device-only mode (localCopy=false) keeps no vault on this computer to serve.\n";
        return 1;
    }
    try {
        fs::create_directories(c.dataPath);
        const std::string vaultPath = c.dataPath + "/vault.json";
        Console console;
        Identity me = loadIdentity();
        const std::string myId = me.id;
        Host host(std::move(me), role, port, address, vaultPath, console);

        // Syncing as a client with this computer's own paired hosts: it keeps them current, and a better one that
        // answers means this network already has its host (PROTOCOL.md §6, one active host per network).
        std::vector<SyncHost> hosts;
        std::map<std::string, std::string> addressOf;
        for (auto& [h, cfg] : loadPairedHosts())
            if (!h.id.empty() && h.id != myId) {
                addressOf[h.id] = h.address;
                hosts.push_back({h.id, h.role, std::make_unique<EspStore>(cfg)});
            }
        VaultService client(std::make_unique<LocalFileStore>(vaultPath), std::move(hosts), c.dataPath + "/sync.json");
        std::string standingFor;  // the better host this one stands down for, "" while serving
        auto check = [&] {
            client.sync();
            std::string better;
            for (const auto& s : client.hostStatuses())
                if (s.status == VaultService::SyncStatus::Ok && (s.role < role || (s.role == role && s.id < myId))) {
                    better = s.id;
                    break;
                }
            if (!better.empty() && better != standingFor) {
                console.setOpen(false);
                host.stop();
                standingFor = better;
                console.say("Standing down: " + addressOf[better] + " hosts this vault here. Still syncing with it.");
            } else if (better.empty() && !host.serving()) {
                standingFor.clear();
                console.setOpen(true);
                host.start();
                console.say("Serving " + vaultPath + " as a " + hostRoleName(role) + " host on port " +
                            std::to_string(port) + " (pairing on " + std::to_string(port + 1) + "), host id " +
                            myId.substr(0, 8) + ".");
            }
        };

        std::cout << term::bold("pwvault host")
                  << ": this terminal is the host's button. Commands: " << term::accent("p") << " open pairing, "
                  << term::accent("d") << " devices, " << term::accent("r <name>") << " revoke, " << term::accent("q")
                  << " quit." << std::endl;
        check();
        auto lastCheck = Clock::now();
        bool input = true;  // stdin still open; without it, nothing can be approved, but syncing goes on
        while (true) {
            pollfd in{STDIN_FILENO, POLLIN, 0};
            if (input && poll(&in, 1, 500) > 0) {
                std::string line;
                if (!std::getline(std::cin, line)) {
                    input = false;
                    console.say("Input closed: requests that need approval will be refused.");
                } else if (!console.answer(line)) {
                    if (line == "q" || line == "quit")
                        break;
                    if (line == "p") {
                        if (host.serving())
                            host.openPairing("");
                        else
                            console.say("Not serving now: another host has this network.");
                    } else if (line == "d") {
                        host.listDevices();
                    } else if (line.rfind("r ", 0) == 0) {
                        console.say(host.revoke(line.substr(2)) ? "Revoked " + line.substr(2) + "."
                                                                : "No device " + line.substr(2) + ".");
                    } else if (!line.empty()) {
                        console.say("Commands: p open pairing, d devices, r <name> revoke, q quit.");
                    }
                }
            } else if (!input) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            console.expire();
            if (Clock::now() - lastCheck > std::chrono::seconds(60)) {
                check();
                lastCheck = Clock::now();
            }
        }
        console.setOpen(false);
        host.stop();
    } catch (const std::exception& e) {
        std::cerr << "Can't serve: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
