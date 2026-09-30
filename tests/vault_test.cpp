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
    return {raw, std::make_unique<VaultService>(std::move(local), std::move(link), (dir / (name + ".sync")).string())};
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
    laptop.vault->changeMasterPassword("new-master");
    phone.vault->sync();
    CHECK(phone.vault->get("gitlab")->password == "pw2");  // still unlocked, still works
    phone.vault->lock();
    CHECK(!phone.vault->unlock("master"));
    CHECK(phone.vault->unlock("new-master"));

    // a different vault pointed at the same ESP32 is refused, not merged
    auto stranger = makeDevice(dir, "stranger", esp);
    auto strangerLocal = std::make_unique<LocalFileStore>((dir / "stranger-solo.json").string());
    VaultService solo(std::move(strangerLocal), nullptr, "");
    solo.create("other", CipherAlg::Aes256Gcm, kFastKdf);
    CHECK(solo.lastSyncStatus() == S::Disabled);
    fs::copy_file(dir / "stranger-solo.json", dir / "stranger.json", fs::copy_options::overwrite_existing);
    CHECK(stranger.vault->sync() == S::Error);
    CHECK(stranger.vault->lastSyncError().find("different vault") != std::string::npos);
    CHECK(laptop.vault->sync() == S::Ok);  // the real vault is untouched

    std::cout << "sync: ok\n";
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
        return std::make_unique<VaultService>(std::move(local), std::make_unique<EspStore>(cfg),
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
    VaultService kiosk(std::move(link), nullptr, "");  // what UIManager builds for localCopy=false
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

int main() {
    fs::path dir = fs::temp_directory_path() / ("vault_test_" + std::to_string(std::random_device{}()));
    fs::create_directories(dir);
    testVectors();
    testMergeRule(dir);
    testSync(dir);
    testRobustness(dir);
    testDeviceOnly(dir);
    if (const char* esp = std::getenv("PWVAULT_TEST_ESP")) testEsp(dir, esp);
    fs::remove_all(dir);
    std::cout << "all vault tests passed\n";
    return 0;
}
