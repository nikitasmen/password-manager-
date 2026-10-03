#include "EspStore.h"

#include <curl/curl.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <thread>

namespace {

constexpr const char* kCertName = "pwvault.local";  // name baked into the ESP32's cert

size_t collect(char* data, size_t size, size_t n, void* out) {
    static_cast<std::string*>(out)->append(data, size * n);
    return size * n;
}

}  // namespace

EspStore::EspStore(EspConfig cfg)
    : cfg_(std::move(cfg)), curl_(curl_easy_init(), [](void* c) { curl_easy_cleanup(static_cast<CURL*>(c)); }) {
    if (!curl_) throw std::runtime_error("curl init failed");
}

EspStore::Response EspStore::request(const std::string& method, const std::string& path, const std::string& body) {
    CURL* c = static_cast<CURL*>(curl_.get());
    curl_easy_reset(c);  // clears options, keeps the open connection
    std::string port = std::to_string(cfg_.port);
    std::string url = std::string("https://") + kCertName + ":" + port + path;

    // Connect to the configured host but verify the cert as pwvault.local (curl's equivalent of /etc/hosts).
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> resolve(nullptr, curl_slist_free_all);
    if (cfg_.host != kCertName)
        resolve.reset(curl_slist_append(nullptr, (std::string(kCertName) + ":" + port + ":" + cfg_.host).c_str()));
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(
        curl_slist_append(nullptr, "Content-Type: application/json"), curl_slist_free_all);

    Response res{0, ""};
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_RESOLVE, resolve.get());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(c, CURLOPT_CAINFO, cfg_.certPath.c_str());
    curl_easy_setopt(c, CURLOPT_SSLCERT, cfg_.clientCert.c_str());
    curl_easy_setopt(c, CURLOPT_SSLKEY, cfg_.clientKey.c_str());
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, 1500L);  // short: "not home" should be detected fast
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, method.c_str());
    if (!body.empty()) curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, collect);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &res.body);

    CURLcode rc = curl_easy_perform(c);
    if (rc == CURLE_COULDNT_CONNECT || rc == CURLE_OPERATION_TIMEDOUT || rc == CURLE_COULDNT_RESOLVE_HOST ||
        rc == CURLE_RECV_ERROR || rc == CURLE_SEND_ERROR)
        throw StoreUnavailable(std::string("ESP32 unreachable: ") + curl_easy_strerror(rc));
    if (rc == CURLE_SSL_CONNECT_ERROR || rc == CURLE_SSL_CERTPROBLEM)
        throw std::runtime_error("ESP32 refused the TLS handshake: check espClientCert/espClientKey (" +
                                 std::string(curl_easy_strerror(rc)) + ")");
    if (rc != CURLE_OK) throw std::runtime_error(std::string("ESP32: ") + curl_easy_strerror(rc));
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &res.status);
    // Other 403s (e.g. a revoke not confirmed on the board) are for the caller
    if (res.status == 403 && res.body.find("device revoked") != std::string::npos)
        throw DeviceRevoked("the host revoked this device, or it was paired again elsewhere; pair it again");
    return res;
}

std::optional<VaultMeta> EspStore::getMeta() {
    auto r = request("GET", "/meta");
    if (r.status == 404) return std::nullopt;
    if (r.status != 200) throw std::runtime_error("GET /meta: HTTP " + std::to_string(r.status));
    return nlohmann::json::parse(r.body).get<VaultMeta>();
}

bool EspStore::putMeta(const VaultMeta& meta, int ifRev) {
    auto r = request("PUT", "/meta", nlohmann::json{{"meta", meta}, {"if_rev", ifRev}}.dump());
    if (r.status == 409) return false;
    if (r.status != 200) throw std::runtime_error("PUT /meta: HTTP " + std::to_string(r.status));
    return true;
}

IVaultStore::Changes EspStore::changesAfter(uint64_t seq) {
    auto r = request("GET", "/entries?after=" + std::to_string(seq));
    if (r.status != 200) throw std::runtime_error("GET /entries: HTTP " + std::to_string(r.status));
    auto j = nlohmann::json::parse(r.body);
    return {j.at("entries").get<std::vector<EntryRecord>>(), j.at("seq").get<uint64_t>()};
}

void EspStore::putEntries(const std::vector<EntryRecord>& entries) {
    auto r = request("POST", "/entries", nlohmann::json{{"entries", entries}}.dump());
    if (r.status != 200) throw std::runtime_error("POST /entries: HTTP " + std::to_string(r.status) + " " + r.body);
}

void EspStore::noteAccess(const std::string& platform, const std::string& username) {
    request("POST", "/access", nlohmann::json{{"platform", platform}, {"username", username}}.dump());
}

std::vector<EspStore::Device> EspStore::devices(Storage* storage, std::string* role) {
    auto r = request("GET", "/devices");
    if (r.status != 200) throw std::runtime_error("GET /devices: HTTP " + std::to_string(r.status));
    auto j = nlohmann::json::parse(r.body);
    std::vector<Device> out;
    for (const auto& d : j.at("devices")) {
        std::string name = d.at("name").get<std::string>();
        out.push_back({name, d.value("seen", int64_t{0}), name == j.value("you", "")});
    }
    if (storage) {
        const auto st = j.value("storage", nlohmann::json::object());
        *storage = {st.value("used", uint64_t{0}), st.value("total", uint64_t{0}), st.value("records", uint64_t{0})};
    }
    if (role) *role = j.value("role", "dedicated");
    return out;
}

void EspStore::revokeDevice(const std::string& name) {
    // The board only records the request (202) and revokes when BOOT is pressed; watch the list until it's gone.
    auto r = request("DELETE", "/devices/" + name);
    if (r.status != 200 && r.status != 202) {
        std::string why = "HTTP " + std::to_string(r.status);
        try {
            why = nlohmann::json::parse(r.body).value("error", why);
        } catch (const nlohmann::json::exception&) {
        }
        throw std::runtime_error("the board didn't revoke " + name + ": " + why);
    }
    for (auto until = std::chrono::steady_clock::now() + std::chrono::seconds(65);;) {
        std::vector<Device> list;
        try {
            list = devices();
        } catch (const DeviceRevoked&) {
            return;  // it was this device: the board now refuses it, which is what we asked for
        }
        if (std::none_of(list.begin(), list.end(), [&](const Device& d) { return d.name == name; })) return;
        if (std::chrono::steady_clock::now() > until) break;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    throw std::runtime_error("BOOT wasn't pressed on the board in time; " + name + " still has access");
}

EspStore::PairInvite EspStore::openPairing() {
    auto r = request("POST", "/pair/open");
    if (r.status != 200) throw std::runtime_error("the board didn't open pairing: HTTP " + std::to_string(r.status));
    auto j = nlohmann::json::parse(r.body);
    return {j.at("code").get<std::string>(), j.at("qr").get<std::string>(), j.value("seconds", 0)};
}

std::string EspStore::setPin(const std::string& verifierHex) {
    auto r = request("PUT", "/pin", nlohmann::json{{"verifier", verifierHex}}.dump());
    if (r.status != 200) throw std::runtime_error("PUT /pin: HTTP " + std::to_string(r.status));
    return nlohmann::json::parse(r.body).at("secret").get<std::string>();
}

EspStore::PinReply EspStore::tryPin(const std::string& proofHex) {
    auto r = request("POST", "/pin", nlohmann::json{{"proof", proofHex}}.dump());
    auto j = nlohmann::json::parse(r.body, nullptr, false);
    if (r.status == 200) return {PinReply::Ok, j.at("secret").get<std::string>()};
    if (r.status == 403) return {PinReply::Wrong, "", j.is_object() ? j.value("left", 0) : 0};
    if (r.status == 410) return {PinReply::Removed};
    if (r.status == 404) return {PinReply::NotSet};
    throw std::runtime_error("POST /pin: HTTP " + std::to_string(r.status));
}
