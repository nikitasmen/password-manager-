// Tests for src/vault: protocol vectors (shared with the Python reference implementation),
// the merge rule, and multi-device sync. The ESP32 is stood in for by a LocalFileStore.
// Run: ./vault_test   (built by CMake; reads tests/protocol_vectors.json)
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <thread>

#include "../src/core/base64.h"
#include "../src/vault/EspStore.h"
#include "../src/vault/LocalFileStore.h"
#include "../src/vault/Pairing.h"
#include "../src/vault/PinUnlock.h"
#include "../src/vault/VaultService.h"

namespace fs = std::filesystem;
using nlohmann::json;

#define CHECK(cond)                                                                        \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond "\n"; \
            std::exit(1);                                                                  \
        }                                                                                  \
    } while (0)

std::string fromHex(const std::string& hex) {
    std::string out;
    for (size_t i = 0; i < hex.size(); i += 2) out += static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16));
    return out;
}

void testVectors() {
    std::ifstream in(VECTORS_PATH);
    CHECK(in);
    json v = json::parse(in);
    std::string vaultKey = fromHex(v["vault_key_hex"]);
    std::string nonce = fromHex(v["nonce_hex"]);
    std::string password = v["password"];

    for (CipherAlg alg : allCiphers()) {
        const json& t = v[cipherName(alg)];
        VaultMeta meta = t["meta"].get<VaultMeta>();
        EntryRecord entry = t["entry"].get<EntryRecord>();
        auto cipher = makeCipher(alg);

        std::string kek = vaultformat::deriveKek(password, meta);
        CHECK(vaultcrypto::toHex(kek) == t["kek_hex"]);
        CHECK(vaultformat::unwrapVaultKey(password, meta) == vaultKey);
        // byte-exact encryption with the vector's nonce
        CHECK(cipher->seal(kek, vaultKey, "pwvault/v1/key", nonce) == meta.key);

        bool rejected = false;
        try {
            vaultformat::unwrapVaultKey("wrong", meta);
        } catch (const WrongPassword&) {
            rejected = true;
        }
        CHECK(rejected);

        CHECK(vaultformat::entryId(vaultKey, "GitHub") == v["entry_id_github"]);
        CHECK(entry.id == v["entry_id_github"]);
        auto cred = vaultformat::openEntry(vaultKey, entry);
        CHECK(cred && cred->platform == "GitHub" && cred->username == "nik" && cred->password == "s3cret");
        CHECK(cred->alg == alg);

        // our serialization of the entry plaintext matches the reference byte for byte
        const std::string plain = R"({"platform":"GitHub","username":"nik","password":"s3cret"})";
        CHECK(cipher->seal(vaultKey, plain, vaultformat::entryAad(entry.id), nonce) == entry.data);
        EntryRecord mine = vaultformat::sealEntry(vaultKey, *cred, entry.updated);
        CHECK(cipher->open(vaultKey, mine.data, vaultformat::entryAad(mine.id)) == plain);

        // AAD binds a blob to its id: moving it to another id must fail
        EntryRecord moved = entry;
        moved.id = std::string(32, 'f');
        bool tamperDetected = false;
        try {
            vaultformat::openEntry(vaultKey, moved);
        } catch (const DecryptError&) {
            tamperDetected = true;
        }
        CHECK(tamperDetected);
    }
    std::cout << "vectors: ok\n";
}

void testMergeRule(const fs::path& dir) {
    LocalFileStore s((dir / "merge.json").string());
    EntryRecord a{"id1", 100, false, "aes-256-gcm", "AAAA", 0};
    s.putEntries({a});
    EntryRecord older = a;
    older.updated = 50;
    older.data = "ZZZZ";
    s.putEntries({older});  // ignored
    CHECK(s.changesAfter(0).entries.at(0).data == "AAAA");
    CHECK(s.changesAfter(0).seq == 1);
    s.putEntries({a});  // identical: ignored, seq unchanged
    CHECK(s.changesAfter(0).seq == 1);
    EntryRecord tie = a;
    tie.data = "BBBB";  // same time, higher data wins
    s.putEntries({tie});
    CHECK(s.changesAfter(0).entries.at(0).data == "BBBB");
    CHECK(s.changesAfter(1).entries.size() == 1 && s.changesAfter(2).entries.empty());

    CHECK(!s.getMeta());
    VaultMeta m;
    m.vaultId = "v";
    CHECK(!s.putMeta(m, 5));  // CAS: wrong expected rev
    CHECK(s.putMeta(m, 0));
    CHECK(!s.putMeta(m, 0));
    CHECK(s.getMeta()->vaultId == "v");
    std::cout << "merge rule: ok\n";
}

// Wraps a store and can pretend to be unreachable, like the ESP32 when you're away from home.
class FlakyStore : public IVaultStore {
   public:
    explicit FlakyStore(IVaultStore& inner) : inner_(inner) {
    }
    bool online = true;
    mutable int contacts = 0;  // requests that reached it (or tried to)
    std::optional<VaultMeta> getMeta() override {
        up();
        return inner_.getMeta();
    }
    bool putMeta(const VaultMeta& m, int r) override {
        up();
        return inner_.putMeta(m, r);
    }
    Changes changesAfter(uint64_t s) override {
        up();
        return inner_.changesAfter(s);
    }
    void putEntries(const std::vector<EntryRecord>& e) override {
        up();
        // same limits as the board (esp32/vault/vault.ino): 32 records, 16 KB body
        if (e.size() > 32 || nlohmann::json{{"entries", e}}.dump().size() > 16 * 1024)
            throw std::runtime_error("413 Payload Too Large");
        inner_.putEntries(e);
    }
    void noteAccess(const std::string& p, const std::string& u) override {
        up();
        lastAccess = p + "/" + u;
    }
    std::string lastAccess;

   private:
    void up() const {
        contacts++;
        if (!online) throw StoreUnavailable("offline");
    }
    IVaultStore& inner_;
};

struct Device {
    FlakyStore* link;
    std::unique_ptr<VaultService> vault;
};

Device makeDevice(const fs::path& dir, const std::string& name, IVaultStore& esp) {
    auto link = std::make_unique<FlakyStore>(esp);
    FlakyStore* raw = link.get();
    auto local = std::make_unique<LocalFileStore>((dir / (name + ".json")).string());
    std::vector<SyncHost> hosts;
    hosts.push_back({"esp", HostRole::Dedicated, std::move(link)});
    return {raw, std::make_unique<VaultService>(std::move(local), std::move(hosts), (dir / (name + ".sync")).string())};
}

void testSync(const fs::path& dir) {
    constexpr int kFastKdf = 1000;
    LocalFileStore esp((dir / "esp.json").string());
    auto laptop = makeDevice(dir, "laptop", esp);
    auto phone = makeDevice(dir, "phone", esp);
    using S = VaultService::SyncStatus;

    // laptop creates the vault; it lands on the ESP32 as ciphertext only
    CHECK(!laptop.vault->exists());
    laptop.vault->create("master", CipherAlg::Aes256Gcm, kFastKdf);
    laptop.vault->put({"GitHub", "nik", "s3cret", CipherAlg::Aes256Gcm});
    CHECK(laptop.vault->lastSyncStatus() == S::Ok);
    std::ifstream espFile(dir / "esp.json");
    std::string espRaw((std::istreambuf_iterator<char>(espFile)), {});
    CHECK(espRaw.find("s3cret") == std::string::npos && espRaw.find("GitHub") == std::string::npos);

    // a fresh phone discovers the vault through the ESP32
    CHECK(phone.vault->exists());
    CHECK(!phone.vault->unlock("wrong"));
    CHECK(phone.vault->unlock("master"));
    auto gh = phone.vault->get("github");  // case-insensitive
    CHECK(gh && gh->password == "s3cret");
    CHECK(phone.link->lastAccess == "GitHub/nik");  // the OLED hint

    // phone adds (with the other cipher) and deletes; laptop sees both
    phone.vault->put({"GitLab", "nik", "pw2", CipherAlg::ChaCha20Poly1305});
    CHECK(phone.vault->remove("GitHub"));
    laptop.vault->sync();
    CHECK(laptop.vault->platforms() == std::vector<std::string>{"GitLab"});
    CHECK(laptop.vault->get("gitlab")->alg == CipherAlg::ChaCha20Poly1305);

    // offline: laptop keeps working locally, catches up when back
    laptop.link->online = false;
    laptop.vault->put({"Mail", "nik", "offline-pw", CipherAlg::Aes256Gcm});
    CHECK(laptop.vault->lastSyncStatus() == S::Offline);
    CHECK(laptop.vault->get("mail")->password == "offline-pw");
    laptop.link->online = true;
    CHECK(laptop.vault->sync() == S::Ok);
    phone.vault->sync();
    CHECK(phone.vault->get("mail")->password == "offline-pw");

    // conflict: both edit Mail offline; the later edit wins everywhere
    laptop.link->online = phone.link->online = false;
    laptop.vault->put({"Mail", "nik", "from-laptop", CipherAlg::Aes256Gcm});
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    phone.vault->put({"Mail", "nik", "from-phone", CipherAlg::Aes256Gcm});
    laptop.link->online = phone.link->online = true;
    laptop.vault->sync();
    phone.vault->sync();
    laptop.vault->sync();
    CHECK(laptop.vault->get("mail")->password == "from-phone");
    CHECK(phone.vault->get("mail")->password == "from-phone");

    // master password change on laptop reaches the phone; entries stay readable (same vault key)
    CHECK(!laptop.vault->changeMasterPassword("not-it", "new-master"));  // must know the current one
    CHECK(laptop.vault->changeMasterPassword("master", "new-master"));
    phone.vault->sync();
    CHECK(phone.vault->get("gitlab")->password == "pw2");  // still unlocked, still works
    phone.vault->lock();
    CHECK(!phone.vault->unlock("master"));
    CHECK(phone.vault->unlock("new-master"));

    // the cipher for new entries is the vault's (PROTOCOL.md §3 entry_alg): set on one device, used on all, and it
    // survives a master password change
    CHECK(phone.vault->entryCipher() == CipherAlg::Aes256Gcm);  // absent = AES
    laptop.vault->setEntryCipher(CipherAlg::ChaCha20Poly1305);
    phone.vault->sync();
    CHECK(phone.vault->entryCipher() == CipherAlg::ChaCha20Poly1305);
    CHECK(phone.vault->changeMasterPassword("new-master", "newer-master"));
    laptop.vault->sync();
    CHECK(laptop.vault->entryCipher() == CipherAlg::ChaCha20Poly1305);
    laptop.vault->put({"Bank", "nik", "pw3", laptop.vault->entryCipher()});
    phone.vault->sync();
    CHECK(phone.vault->get("bank")->alg == CipherAlg::ChaCha20Poly1305);

    // a different vault pointed at the same ESP32 is refused, not merged
    auto stranger = makeDevice(dir, "stranger", esp);
    auto strangerLocal = std::make_unique<LocalFileStore>((dir / "stranger-solo.json").string());
    VaultService solo(std::move(strangerLocal), std::vector<SyncHost>{}, "");
    solo.create("other", CipherAlg::Aes256Gcm, kFastKdf);
    CHECK(solo.lastSyncStatus() == S::Disabled);
    fs::copy_file(dir / "stranger-solo.json", dir / "stranger.json", fs::copy_options::overwrite_existing);
    CHECK(stranger.vault->sync() == S::Error);
    CHECK(stranger.vault->lastSyncError().find("different vault") != std::string::npos);
    CHECK(laptop.vault->sync() == S::Ok);  // the real vault is untouched

    std::cout << "sync: ok\n";
}

// PROTOCOL.md §8, several hosts: a board (dedicated) and a laptop (peer). The phone has both; the desktop only the
// board; the pi only the laptop. Changes still reach everyone, through the phone.
void testHosts(const fs::path& dir) {
    using S = VaultService::SyncStatus;
    LocalFileStore boardStore((dir / "h-board.json").string()), laptopStore((dir / "h-laptop.json").string());
    struct Dev {
        std::vector<FlakyStore*> links;
        std::unique_ptr<VaultService> vault;
    };
    auto device = [&](const std::string& name, std::vector<std::pair<std::string, IVaultStore*>> to) {
        Dev d;
        std::vector<SyncHost> hosts;
        for (auto& [id, store] : to) {
            auto link = std::make_unique<FlakyStore>(*store);
            d.links.push_back(link.get());
            hosts.push_back({id, id == "board" ? HostRole::Dedicated : HostRole::Peer, std::move(link)});
        }
        d.vault =
            std::make_unique<VaultService>(std::make_unique<LocalFileStore>((dir / ("h-" + name + ".json")).string()),
                                           std::move(hosts),
                                           (dir / ("h-" + name + ".sync")).string());
        return d;
    };
    Dev phone = device("phone", {{"laptop", &laptopStore}, {"board", &boardStore}});  // listed worst first
    Dev desk = device("desk", {{"board", &boardStore}});
    Dev pi = device("pi", {{"laptop", &laptopStore}});

    phone.vault->create("master", CipherAlg::Aes256Gcm, 1000);  // lands on both hosts
    CHECK(boardStore.getMeta() && laptopStore.getMeta());
    const auto& hs = phone.vault->hostStatuses();
    CHECK(hs.size() == 2 && hs[0].id == "board" && hs[1].id == "laptop");  // best role first
    CHECK(hs[0].status == S::Ok && hs[1].status == S::Ok);

    // the pi writes through the laptop; the phone carries it to the board; the desktop reads it there
    CHECK(pi.vault->unlock("master"));
    pi.vault->put({"Pi", "u", "from-pi", CipherAlg::Aes256Gcm});
    CHECK(desk.vault->unlock("master"));
    CHECK(!desk.vault->get("pi"));
    CHECK(phone.vault->unlock("master"));  // pulls it from the laptop after the board: the board gets it next round
    phone.vault->sync();
    desk.vault->sync();
    CHECK(desk.vault->get("pi") && desk.vault->get("pi")->password == "from-pi");
    // and back: the desktop's edit reaches the pi
    desk.vault->put({"Pi", "u", "from-desk", CipherAlg::Aes256Gcm});
    phone.vault->sync();
    pi.vault->sync();
    CHECK(pi.vault->get("pi")->password == "from-desk");

    // one host away: still Ok, and that host says why. The OLED hint (platform and username, in the clear) goes only
    // to a dedicated host: with the board away, the laptop must not get it (PROTOCOL.md §7, §12)
    phone.links[0]->online = false;  // links are in the order given: [0] laptop
    phone.links[1]->online = false;  // [1] board
    CHECK(phone.vault->sync() == S::Offline);
    phone.links[0]->online = true;
    CHECK(phone.vault->sync() == S::Ok);
    CHECK(phone.vault->hostStatuses()[0].status == S::Offline && phone.vault->hostStatuses()[1].status == S::Ok);
    phone.vault->get("pi");
    CHECK(phone.links[0]->lastAccess.empty());
    // back on the board's network: the board was offline a moment ago, so while the laptop answers it's skipped...
    phone.links[1]->online = true;
    phone.links[1]->lastAccess.clear();
    CHECK(phone.vault->sync() == S::Ok);
    CHECK(phone.vault->hostStatuses()[0].status == S::Offline);
    // ...and once the laptop is gone (one active host per network), it's tried at once
    phone.links[0]->online = false;
    CHECK(phone.vault->sync() == S::Ok);
    CHECK(phone.vault->hostStatuses()[0].status == S::Ok);
    phone.vault->get("pi");
    CHECK(phone.links[1]->lastAccess == "Pi/u");
    phone.links[0]->online = true;

    // a host with another vault is skipped and reported; the others still sync
    LocalFileStore strangerStore((dir / "h-stranger.json").string());
    {
        VaultService other(
            std::make_unique<LocalFileStore>((dir / "h-other.json").string()), std::vector<SyncHost>{}, "");
        other.create("x", CipherAlg::Aes256Gcm, 1000);
        strangerStore.putMeta(*LocalFileStore((dir / "h-other.json").string()).getMeta(), 0);
    }
    fs::copy_file(dir / "h-phone.json", dir / "h-phone2.json");
    Dev phone2 = device("phone2", {{"board", &boardStore}, {"stranger", &strangerStore}});
    CHECK(phone2.vault->unlock("master"));
    CHECK(phone2.vault->lastSyncStatus() == S::Ok);
    CHECK(phone2.vault->hostStatuses()[1].status == S::Error);
    CHECK(phone2.vault->hostStatuses()[1].error.find("different vault") != std::string::npos);

    // cursors: one pair per host; a v1 cursor file reads as "sync everything" and is replaced
    std::ifstream in(dir / "h-phone.sync");
    auto state = nlohmann::json::parse(in);
    CHECK(state["hosts"].contains("board") && state["hosts"].contains("laptop"));
    std::ofstream(dir / "h-desk.sync", std::ios::trunc) << R"({"vault_id":"x","local_seq":99,"remote_seq":99})";
    CHECK(desk.vault->sync() == S::Ok);
    std::ifstream in2(dir / "h-desk.sync");
    CHECK(nlohmann::json::parse(in2)["hosts"].contains("board"));
    // hosts come and go at runtime: a new one slots in by role, a forgotten one loses its cursors
    LocalFileStore serverStore((dir / "h-server.json").string());
    desk.vault->addHost({"server", HostRole::Server, std::make_unique<FlakyStore>(serverStore)});
    CHECK(desk.vault->hostStatuses().size() == 2 && desk.vault->hostStatuses()[1].id == "server");
    CHECK(desk.vault->sync() == S::Ok && serverStore.getMeta());
    desk.vault->removeHost("server");
    std::ifstream in3(dir / "h-desk.sync");
    auto after = nlohmann::json::parse(in3)["hosts"];
    CHECK(desk.vault->hostStatuses().size() == 1 && !after.contains("server") && after.contains("board"));
    std::cout << "hosts: ok (role order; changes cross hosts; away hosts skipped; foreign hosts reported; per-host "
                 "cursors; add/forget)\n";
}

// Real-hardware test, only when PWVAULT_TEST_ESP="host[:port],serverCert,clientCert,clientKey" is set
// (the real board, or tests/fake_esp.py).
// Refuses to run against a board that already holds a vault. Leaves a test vault behind: wipe the board after.
void testEsp(const fs::path& dir, const std::string& spec) {
    EspConfig cfg;
    std::stringstream ss(spec);
    std::getline(ss, cfg.host, ',');
    std::getline(ss, cfg.certPath, ',');
    std::getline(ss, cfg.clientCert, ',');
    std::getline(ss, cfg.clientKey, ',');
    if (auto colon = cfg.host.find(':'); colon != std::string::npos) {  // "host:port", e.g. tests/fake_esp.py
        cfg.port = std::stoi(cfg.host.substr(colon + 1));
        cfg.host.resize(colon);
    }
    EspStore esp(cfg);
    // Read-only auth checks first: safe even on a board that holds a real vault
    esp.getMeta();  // throws if our certificate isn't accepted
    EspConfig noCert = cfg;  // no client certificate: the board refuses the handshake
    noCert.clientCert = noCert.clientKey = "";
    bool rejected = false;
    try {
        EspStore(noCert).getMeta();
    } catch (const StoreUnavailable&) {
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    CHECK(rejected);
    EspConfig away = cfg;
    away.host = "192.0.2.1";  // TEST-NET: nothing there
    bool offline = false;
    try {
        EspStore(away).getMeta();
    } catch (const StoreUnavailable&) {
        offline = true;
    }
    CHECK(offline);
    std::cout << "esp auth: ok (cert accepted; no cert refused; unreachable = offline)\n";
    // Device list: we're on it, exactly once, and just seen. Revoking an unknown name fails before any BOOT prompt.
    auto devices = esp.devices();
    CHECK(std::count_if(devices.begin(), devices.end(), [](const auto& d) { return d.thisDevice; }) == 1);
    for (const auto& d : devices)
        if (d.thisDevice) CHECK(d.lastSeen == 0 || std::time(nullptr) - d.lastSeen < 120);
    bool refused = false;
    try {
        esp.revokeDevice("no-such-device");
    } catch (const StoreUnavailable&) {
    } catch (const std::runtime_error& e) {
        refused = std::string(e.what()).find("no such device") != std::string::npos;
    }
    CHECK(refused);
    std::cout << "esp devices: ok (" << devices.size() << " paired)\n";
    if (esp.getMeta()) {
        std::cout << "esp: SKIPPED (board already holds a vault; wipe it first)\n";
        return;
    }
    auto makeEspDevice = [&](const std::string& name) {
        auto local = std::make_unique<LocalFileStore>((dir / (name + ".json")).string());
        std::vector<SyncHost> hosts;
        hosts.push_back({"esp", HostRole::Dedicated, std::make_unique<EspStore>(cfg)});
        return std::make_unique<VaultService>(std::move(local), std::move(hosts),
                                              (dir / (name + ".sync")).string());
    };
    using S = VaultService::SyncStatus;
    auto a = makeEspDevice("esp-a");
    auto b = makeEspDevice("esp-b");
    a->create("master", CipherAlg::Aes256Gcm, 1000);
    CHECK(a->lastSyncStatus() == S::Ok);
    for (int i = 0; i < 40; i++)  // more than one POST batch
        a->put({"site" + std::to_string(i), "user", "pw" + std::to_string(i), allCiphers()[i % 2]});
    a->put({"GitHub", "nik", "s3cret", CipherAlg::ChaCha20Poly1305});
    CHECK(a->lastSyncStatus() == S::Ok);

    auto raw = esp.changesAfter(0);
    CHECK(raw.entries.size() == 41);
    for (const auto& e : raw.entries) CHECK(e.data.find("s3cret") == std::string::npos);

    CHECK(b->unlock("master"));
    CHECK(b->platforms().size() == 41);
    CHECK(b->get("github")->password == "s3cret");  // OLED should show: esp-b... wants GitHub / nik
    CHECK(b->remove("site0"));
    a->sync();
    CHECK(!a->get("site0"));
    CHECK(esp.putMeta(*esp.getMeta(), 0) == false);  // CAS conflict -> 409

    std::cout << "esp: ok (" << raw.entries.size() << " records round-tripped through the board)\n";
}

// Code-review regressions: store resets, batch size, concurrent writers, input validation.
void testRobustness(const fs::path& dir) {
    constexpr int kFastKdf = 1000;
    using S = VaultService::SyncStatus;
    LocalFileStore esp((dir / "r-esp.json").string());
    auto laptop = makeDevice(dir, "r-laptop", esp);
    laptop.vault->create("master", CipherAlg::Aes256Gcm, kFastKdf);
    for (int i = 0; i < 5; i++) laptop.vault->put({"site" + std::to_string(i), "u", "p", CipherAlg::Aes256Gcm});

    // board wiped/reflashed: the next sync must re-upload everything, not just recent changes
    fs::remove(dir / "r-esp.json");
    CHECK(laptop.vault->sync() == S::Ok);
    CHECK(esp.changesAfter(0).entries.size() == 5);
    auto fresh = makeDevice(dir, "r-fresh", esp);
    CHECK(fresh.vault->unlock("master") && fresh.vault->platforms().size() == 5);

    // local vault.json deleted (sync cursors kept): the next sync must pull everything back
    fs::remove(dir / "r-laptop.json");
    CHECK(laptop.vault->sync() == S::Ok);
    laptop.vault->lock();
    CHECK(laptop.vault->unlock("master") && laptop.vault->platforms().size() == 5);

    // many large entries saved offline go out in batches the board accepts (count AND bytes)
    laptop.link->online = false;
    for (int i = 0; i < 40; i++) laptop.vault->put({"big" + std::to_string(i), "u", std::string(300, 'x'), CipherAlg::Aes256Gcm});
    laptop.link->online = true;
    CHECK(laptop.vault->sync() == S::Ok);
    CHECK(esp.changesAfter(0).entries.size() == 45);

    // input validation
    bool rejectedEmpty = false, rejectedHuge = false;
    try {
        laptop.vault->put({"x", "user", "", CipherAlg::Aes256Gcm});
    } catch (const std::invalid_argument&) {
        rejectedEmpty = true;
    }
    try {
        laptop.vault->put({"x", "user", std::string(20000, 'x'), CipherAlg::Aes256Gcm});
    } catch (const std::invalid_argument&) {
        rejectedHuge = true;
    }
    CHECK(rejectedEmpty && rejectedHuge);

    // two app instances writing the same vault.json at once lose nothing
    auto writer = [&](int who) {
        LocalFileStore s((dir / "r-shared.json").string());
        for (int i = 0; i < 50; i++) {
            EntryRecord e{vaultcrypto::toHex(vaultcrypto::randomBytes(16)), 1, false, "aes-256-gcm", "d", 0};
            s.putEntries({e});
        }
        (void)who;
    };
    std::thread t1(writer, 1), t2(writer, 2);
    t1.join();
    t2.join();
    LocalFileStore shared((dir / "r-shared.json").string());
    CHECK(shared.changesAfter(0).entries.size() == 100 && shared.changesAfter(0).seq == 100);

    // a corrupt sync.json means "sync everything", not "fail forever"
    std::ofstream(dir / "r-laptop.sync", std::ios::trunc) << "{garbage";
    CHECK(laptop.vault->sync() == S::Ok);
    std::cout << "robustness: ok\n";
}

// localCopy=false: the board is the device's only store; every read reaches it.
void testDeviceOnly(const fs::path& dir) {
    using S = VaultService::SyncStatus;
    LocalFileStore esp((dir / "d-esp.json").string());
    auto laptop = makeDevice(dir, "d-laptop", esp);  // an ordinary local-first device
    laptop.vault->create("master", CipherAlg::Aes256Gcm, 1000);
    laptop.vault->put({"GitHub", "nik", "v1", CipherAlg::Aes256Gcm});

    auto link = std::make_unique<FlakyStore>(esp);
    FlakyStore* board = link.get();
    VaultService kiosk(std::move(link), std::vector<SyncHost>{}, "");  // what UIManager builds for localCopy=false
    CHECK(kiosk.exists() && kiosk.unlock("master"));
    CHECK(kiosk.get("github")->password == "v1");
    CHECK(board->lastAccess == "GitHub/nik");  // the OLED hears about every read

    laptop.vault->put({"GitHub", "nik", "v2", CipherAlg::Aes256Gcm});  // another device changes it...
    CHECK(kiosk.get("github")->password == "v2");                      // ...and the next read sees it, no sync step

    kiosk.put({"Mail", "nik", "m1", CipherAlg::ChaCha20Poly1305});  // writes land on the board directly
    laptop.vault->sync();
    CHECK(laptop.vault->get("mail")->password == "m1");

    board->online = false;  // no local copy to fall back on: the read fails, and the status says why
    bool threw = false;
    try {
        kiosk.get("github");
    } catch (const StoreUnavailable&) {
        threw = true;
    }
    CHECK(threw && kiosk.lastSyncStatus() == S::Offline);
    board->online = true;
    CHECK(kiosk.get("github") && kiosk.lastSyncStatus() == S::Disabled);
    std::cout << "device-only: ok\n";
}

// Pairing through the app's client, only against tests/fake_esp.py (always open, auto-approves):
// PWVAULT_TEST_PAIR="host:mainPort:pairPort,code". Not the real board: a wrong code closes its pairing mode.
void testPair(const fs::path& dir, const std::string& spec) {
    std::string addr = spec.substr(0, spec.find(',')), code = normalizePairCode(spec.substr(spec.find(',') + 1));
    const std::string host = addr.substr(0, addr.find(':'));
    const int port = std::stoi(addr.substr(addr.find(':') + 1)), pairPort = std::stoi(addr.substr(addr.rfind(':') + 1));
    CHECK(!code.empty() && normalizePairCode("abcd-o123-efgh-4567") == "ABCD0123EFGH4567" && normalizePairCode("short").empty());
    CHECK(validDeviceName("laptop-2") && !validDeviceName("-x") && !validDeviceName("Laptop") && !validDeviceName(""));
    bool wrong = false, closed = false;
    try {
        pairWithBoard(host, pairPort, "pair-test", std::string(16, 'Z'));
    } catch (const PairError& e) {
        wrong = std::string(e.what()).find("wrong code") != std::string::npos;
    }
    try {
        pairWithBoard(host, 1, "pair-test", code);  // nothing listens there
    } catch (const PairError&) {
        closed = true;
    }
    CHECK(wrong && closed);
    PairedFiles f = pairWithBoard(host, pairPort, "pair-test", code);
    CHECK(certFingerprint(f.serverPem).size() == 64 && certFingerprint("not a cert").empty());  // the host id
    auto put = [&](const char* n, const std::string& s) { return std::ofstream(dir / n) << s, (dir / n).string(); };
    EspStore esp(EspConfig{host, port, put("server.pem", f.serverPem), put("device.pem", f.certPem), put("device.key", f.keyPem)});
    esp.getMeta();  // throws unless the board accepts the certificate it just issued
    EspStore::Storage storage;
    auto devices = esp.devices(&storage);
    CHECK(std::any_of(devices.begin(), devices.end(), [](const auto& d) { return d.thisDevice && d.name == "pair-test"; }));
    CHECK(storage.total > 0 && storage.used <= storage.total);  // §7 storage, which the Devices screens show
    std::cout << "pair: ok (wrong code refused, no pairing port reported, issued cert accepted)\n";
    // A paired device opens pairing for another (the laptop showing a QR for a phone): same code, QR per §9
    const EspStore::PairInvite invite = esp.openPairing();
    CHECK(invite.code == code && invite.qr == "PWVAULT:" + host + ":" + code && invite.seconds > 0);
    std::cout << "pair/open: ok\n";

    // PIN unlock only on a dedicated host (§11): any other answers 404, which EspStore reports as an error
    std::string role;
    esp.devices(nullptr, &role);
    if (role != "dedicated") {
        bool refused = false;
        try {
            esp.setPin(std::string(64, 'a'));
        } catch (const std::runtime_error&) {
            refused = true;
        }
        CHECK(refused && esp.tryPin(std::string(64, 'a')).result == EspStore::PinReply::NotSet);
        std::cout << "pin: ok (a " << role << " host offers none)\n";
        return;
    }
    // PIN unlock through the board: the vault key sealed under HMAC(board secret, PIN proof)
    CHECK(validPin("1234") && validPin("00000000") && !validPin("123") && !validPin("12a4") && !validPin(""));
    VaultService v(std::make_unique<LocalFileStore>((dir / "pin-vault.json").string()), std::vector<SyncHost>{}, "");
    v.create("master", CipherAlg::Aes256Gcm, 1000);
    v.put({"mail", "me", "pw", CipherAlg::Aes256Gcm});
    const std::string salt = vaultcrypto::randomBytes(16), proof = pinProofHex("2468", salt, 1000),
                      wrongProof = pinProofHex("1357", salt, 1000);
    const std::string blob = v.sealKeyForPin(pinWrapKey(esp.setPin(vaultcrypto::sha256Hex(proof)), proof));
    v.lock();
    auto r = esp.tryPin(proof);
    CHECK(r.result == EspStore::PinReply::Ok && v.unlockWithPinKey(pinWrapKey(r.secretHex, proof), blob));
    CHECK(v.get("mail")->password == "pw");
    for (int left = 4; left >= 1; left--) CHECK(esp.tryPin(wrongProof).triesLeft == left);
    CHECK(esp.tryPin(proof).result == EspStore::PinReply::Ok);  // the right PIN resets the count
    for (int i = 0; i < 4; i++) CHECK(esp.tryPin(wrongProof).result == EspStore::PinReply::Wrong);
    CHECK(esp.tryPin(wrongProof).result == EspStore::PinReply::Removed);  // the 5th: gone
    CHECK(esp.tryPin(proof).result == EspStore::PinReply::NotSet);        // even the right PIN, now
    VaultService other(
        std::make_unique<LocalFileStore>((dir / "other-vault.json").string()), std::vector<SyncHost>{}, "");
    other.create("master", CipherAlg::Aes256Gcm, 1000);
    other.lock();
    CHECK(!other.unlockWithPinKey(pinWrapKey(r.secretHex, proof), blob));  // bound to its own vault
    std::cout << "pin: ok (unlocks; 5 wrong tries remove it; bound to its vault)\n";
}

// A host holds ciphertext only and isn't trusted (PROTOCOL.md §12): whatever it does to the records, a client never
// shows one entry's secret under another's name, and never crashes. It can only make entries unreadable.
void testHostileHost(const fs::path& dir) {
    LocalFileStore host((dir / "x-host.json").string());
    auto writer = makeDevice(dir, "x-writer", host);
    writer.vault->create("master", CipherAlg::Aes256Gcm, 1000);
    const std::map<std::string, std::string> secret = {{"GitHub", "gh-secret"}, {"Mail", "mail-secret"},
                                                       {"Bank", "bank-secret"}};
    for (const auto& [platform, pw] : secret) writer.vault->put({platform, "nik", pw, CipherAlg::Aes256Gcm});
    std::vector<EntryRecord> all = host.changesAfter(0).entries;
    CHECK(all.size() == 3);

    // 1. One record's ciphertext changed (and dated newer, so the merge rule takes it)
    EntryRecord flipped = all[0];
    flipped.data[flipped.data.size() / 2] = flipped.data[flipped.data.size() / 2] == 'A' ? 'B' : 'A';
    flipped.updated += 1000;
    // 2. Another record's ciphertext moved onto a different id: its AAD binds it to its own id
    EntryRecord moved = all[2];
    moved.id = all[1].id;
    moved.updated = all[1].updated + 1000;
    host.putEntries({flipped, moved});

    auto reader = makeDevice(dir, "x-reader", host);
    CHECK(reader.vault->unlock("master"));
    CHECK(reader.vault->platforms().size() == 1);  // only the untouched one opens; the others are skipped
    for (const auto& [platform, pw] : secret)
        if (auto got = reader.vault->get(platform)) CHECK(got->platform == platform && got->password == pw);

    // 3. The vault key blob changed: the master password no longer opens it, and that's a clean "no"
    VaultMeta m = *host.getMeta();
    m.key[m.key.size() / 2] = m.key[m.key.size() / 2] == 'A' ? 'B' : 'A';
    m.rev += 1;
    CHECK(host.putMeta(m, m.rev - 1));
    auto locked = makeDevice(dir, "x-locked", host);
    bool opened = true;
    try {
        opened = locked.vault->unlock("master");
    } catch (const std::exception& e) {
        std::cerr << "unlock threw: " << e.what() << "\n";
    }
    CHECK(!opened);
    std::cout << "hostile host: ok (changed and moved records don't open; a changed key blob doesn't unlock)\n";
}

// Hosts of one role sort by id, so "the" PIN host and the sync order are the same on every start; PIN unlock goes
// to the host pin.json names; and hosts the startup check found away aren't waited on again by the next sync.
void testHostOrderAndChecks(const fs::path& dir) {
    LocalFileStore s1((dir / "o-1.json").string()), s2((dir / "o-2.json").string()), s3((dir / "o-3.json").string());
    auto b = std::make_unique<FlakyStore>(s1), a = std::make_unique<FlakyStore>(s2),
         c = std::make_unique<FlakyStore>(s3);
    FlakyStore *pa = a.get(), *pb = b.get(), *pc = c.get();
    std::vector<SyncHost> hosts;
    hosts.push_back({"bbbb", HostRole::Dedicated, std::move(b)});  // added out of order on purpose
    hosts.push_back({"cccc", HostRole::Server, std::move(c)});
    hosts.push_back({"aaaa", HostRole::Dedicated, std::move(a)});
    VaultService v(std::make_unique<LocalFileStore>((dir / "o-local.json").string()), std::move(hosts),
                   (dir / "o.sync").string());
    std::vector<std::string> order;
    for (const auto& s : v.hostStatuses()) order.push_back(s.id);
    CHECK((order == std::vector<std::string>{"aaaa", "bbbb", "cccc"}));

    CHECK(pinHostId(PinFile{"", 1, "", "bbbb"}, {"aaaa", "bbbb"}) == "bbbb");  // the one it names, not the first
    CHECK(pinHostId(PinFile{"", 1, "", ""}, {"aaaa", "bbbb"}) == "aaaa");      // from before: the best one
    CHECK(pinHostId(PinFile{"", 1, "", "gone"}, {"aaaa", "bbbb"}).empty());    // its host was forgotten
    CHECK(pinHostId(PinFile{"", 1, "", ""}, {}).empty());

    v.create("master", CipherAlg::Aes256Gcm, 1000);
    using S = VaultService::SyncStatus;
    pa->online = pb->online = false;
    v.noteOffline({"aaaa", "bbbb"});  // the startup check found the two boards away
    int before = pa->contacts + pb->contacts;
    CHECK(v.sync() == S::Ok);                      // through the server host
    CHECK(pa->contacts + pb->contacts == before);  // the boards weren't waited on again
    pc->online = false;
    v.noteOffline({"aaaa", "bbbb", "cccc"});  // all three away
    before = pa->contacts + pb->contacts + pc->contacts;
    CHECK(v.sync() == S::Offline);
    CHECK(pa->contacts + pb->contacts + pc->contacts == before);  // nothing to wait on: offline at once

    // Forgetting hosts recomputes the status from the ones left
    LocalFileStore r1((dir / "o-r1.json").string()), r2((dir / "o-r2.json").string());
    auto up = std::make_unique<FlakyStore>(r1), down = std::make_unique<FlakyStore>(r2);
    down->online = false;
    std::vector<SyncHost> two;
    two.push_back({"up", HostRole::Dedicated, std::move(up)});
    two.push_back({"down", HostRole::Server, std::move(down)});
    VaultService w(std::make_unique<LocalFileStore>((dir / "o-w.json").string()), std::move(two),
                   (dir / "o-w.sync").string());
    w.create("master", CipherAlg::Aes256Gcm, 1000);
    CHECK(w.lastSyncStatus() == S::Ok);
    w.removeHost("up");  // the only one that synced: the status can't stay Ok
    CHECK(w.lastSyncStatus() == S::Offline);
    w.removeHost("down");
    CHECK(w.lastSyncStatus() == S::Disabled && w.lastSyncError().empty());  // no host left: not a stale result
    std::cout << "host order and checks: ok\n";
}

// Forgetting or re-pairing a host deletes pin.json only if the PIN is that host's (PROTOCOL.md §11)
void testPinOwnership() {
    PinFile old{"salt", 1, "blob", ""};  // from before there were several hosts: the PIN host's alone
    CHECK(pinBelongsTo(old, "board", "board"));
    CHECK(!pinBelongsTo(old, "laptop", "board"));  // re-pairing the laptop must keep the board's PIN
    CHECK(!pinBelongsTo(old, "laptop", ""));
    PinFile named{"salt", 1, "blob", "board"};
    CHECK(pinBelongsTo(named, "board", "other"));
    CHECK(!pinBelongsTo(named, "laptop", "laptop"));
    std::cout << "pin ownership: ok\n";
}

int main() {
    fs::path dir = fs::temp_directory_path() / ("vault_test_" + std::to_string(std::random_device{}()));
    fs::create_directories(dir);
    testVectors();
    testMergeRule(dir);
    testSync(dir);
    testHosts(dir);
    testRobustness(dir);
    testDeviceOnly(dir);
    testPinOwnership();
    testHostOrderAndChecks(dir);
    testHostileHost(dir);
    if (const char* esp = std::getenv("PWVAULT_TEST_ESP")) testEsp(dir, esp);
    if (const char* pair = std::getenv("PWVAULT_TEST_PAIR")) testPair(dir, pair);
    fs::remove_all(dir);
    std::cout << "all vault tests passed\n";
    return 0;
}
