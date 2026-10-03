#include "UIManager.h"

#include <algorithm>
#include <unistd.h>

#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

#include "../core/base64.h"
#include "../utils/EncryptionUtils.h"
#include "../vault/Crypto.h"
#include "../vault/EspStore.h"
#include "../vault/LocalFileStore.h"

namespace {
// "192.168.1.5" -> the board's port 443; "host:8443" -> 8443
std::pair<std::string, int> splitAddress(const std::string& a) {
    auto colon = a.rfind(':');
    if (colon == std::string::npos) return {a, 443};
    try {
        return {a.substr(0, colon), std::stoi(a.substr(colon + 1))};
    } catch (const std::exception&) {
        return {a, 443};
    }
}

// Run a vault call for the UI: log a failure and return `fallback` instead of throwing into UI code.
template <class R, class F>
R guarded(const char* what, R fallback, F&& call) {
    try {
        return call();
    } catch (const std::exception& e) {
        std::cerr << "Error " << what << ": " << e.what() << std::endl;
        return fallback;
    }
}
}  // namespace

// Throws if the vault can't be set up (e.g. unwritable dataPath): tui_main/gui_main report it and exit,
// so no UI code ever runs with a null vault. Stores:
//   local-first (default): the local file, synced with every paired host
//   device-only (localCopy=false): the best host as the only store, nothing written to dataPath
UIManager::UIManager(const std::string& dataPath) : isLoggedIn(false), dataPath(dataPath) {
    namespace fs = std::filesystem;
    const AppConfig& c = ConfigManager::getInstance().getConfig();
    deviceOnly_ = !c.localCopy;
    std::vector<SyncHost> hosts;
    for (auto& [h, cfg] : loadPairedHosts()) {
        auto store = std::make_unique<EspStore>(cfg);
        h.store = store.get();
        auto at = std::find_if(hosts_.begin(), hosts_.end(), [&](const PairedHost& o) { return o.role > h.role; });
        hosts.insert(hosts.begin() + (at - hosts_.begin()), SyncHost{h.id, h.role, std::move(store)});
        hosts_.insert(at, h);
    }
    if (deviceOnly_) {
        if (hosts.empty() && c.espHost.empty())
            throw std::runtime_error("localCopy=false (device-only) needs a host: set espHost in " +
                                     ConfigManager::configFile() + " and pair with it");
        // No host yet: the config's address, unpaired, until the connector pairs it
        vault = std::make_unique<VaultService>(
            hosts.empty() ? std::make_unique<EspStore>(EspConfig{c.espHost, c.espPort, "", "", ""})
                          : std::move(hosts.front().store),
            std::vector<SyncHost>{}, "");
        hosts_.resize(std::min<size_t>(hosts_.size(), 1));  // the one store; the others aren't used
        return;
    }
    fs::create_directories(dataPath);
    vault = std::make_unique<VaultService>(std::make_unique<LocalFileStore>(dataPath + "/vault.json"), std::move(hosts),
                                           dataPath + "/sync.json");
}

namespace {
// One host's folder: the three PEMs, and `host` (address=, role=); each mode 600, via .tmp + rename.
void writeHostFile(const std::string& path, const std::string& content) {
    writePrivateTmp(path, content);
    std::filesystem::rename(path + ".tmp", path);
}

void saveHost(const std::string& dir, const PairedFiles& f, const std::string& address, HostRole role) {
    writeHostFile(dir + "/server.pem", f.serverPem);
    writeHostFile(dir + "/device.pem", f.certPem);
    writeHostFile(dir + "/device.key", f.keyPem);
    writeHostFile(dir + "/host", "address=" + address + "\nrole=" + hostRoleName(role) + "\n");
}

// A pairing in the config's esp* keys (made before hosts/ existed, or by esp32/pki.sh pair) moves into hosts/
// once, so every host lives in one place. An espHost without certs stays: the connector pairs it.
void moveConfigHost() {
    namespace fs = std::filesystem;
    ConfigManager& cm = ConfigManager::getInstance();
    const AppConfig c = cm.getConfig();
    const PairedFiles f{readFile(c.espCert), readFile(c.espClientCert), readFile(c.espClientKey)};
    const std::string id = certFingerprint(f.serverPem);
    if (c.espHost.empty() || id.empty() || f.certPem.empty() || f.keyPem.empty()) return;
    saveHost(hostsDir() + "/" + id.substr(0, 16), f,
             c.espHost + (c.espPort == 443 ? "" : ":" + std::to_string(c.espPort)), HostRole::Dedicated);
    AppConfig next = c;
    next.espHost.clear();
    cm.updateConfig(next);
    if (!cm.saveConfig()) return;  // the old files stay while the config still points at them
    std::error_code ec;
    for (const std::string& p : {c.espCert, c.espClientCert, c.espClientKey})
        if (fs::path(p).parent_path() == fs::path(ConfigManager::configDir())) fs::remove(p, ec);  // only ours
}
}  // namespace

std::vector<std::pair<PairedHost, EspConfig>> loadPairedHosts() {
    namespace fs = std::filesystem;
    moveConfigHost();
    std::vector<std::pair<PairedHost, EspConfig>> out;
    std::error_code ec;
    for (const auto& d : fs::directory_iterator(hostsDir(), ec)) {
        std::map<std::string, std::string> kv;  // host: address=, role=
        std::istringstream in(readFile((d.path() / "host").string()));
        for (std::string line; std::getline(in, line);)
            if (auto eq = line.find('='); eq != std::string::npos) kv[line.substr(0, eq)] = line.substr(eq + 1);
        const std::string dir = d.path().string(), id = certFingerprint(readFile(dir + "/server.pem"));
        if (kv["address"].empty() || id.empty()) continue;
        auto [addr, port] = splitAddress(kv["address"]);
        out.emplace_back(PairedHost{id, kv["address"], hostRoleOf(kv["role"]), dir},
                         EspConfig{addr, port, dir + "/server.pem", dir + "/device.pem", dir + "/device.key"});
    }
    return out;
}

bool UIManager::safeAddCredential(const std::string& platform,
                                  const std::string& username,
                                  const std::string& password,
                                  std::optional<CipherAlg> encryptionType) {
    return guarded("adding credential", false, [&] {
        vault->put({platform, username, password, encryptionType.value_or(encryption_utils::getDefault())});
        return true;
    });
}

std::optional<Credential> UIManager::safeGetCredentials(const std::string& platform) {
    return guarded("getting credentials", std::optional<Credential>{}, [&] { return vault->get(platform); });
}

bool UIManager::safeDeleteCredential(const std::string& platform) {
    return guarded("deleting credential", false, [&] { return vault->remove(platform); });
}

std::vector<std::string> UIManager::safeGetPlatforms() {
    return guarded("listing platforms", std::vector<std::string>{}, [&] { return vault->platforms(); });
}

bool UIManager::safeChangeMasterPassword(const std::string& current,
                                         const std::string& next,
                                         const std::string& repeat,
                                         std::string& error) {
    const size_t minLen = static_cast<size_t>(ConfigManager::getInstance().getConfig().minPasswordLength);
    if (next != repeat) error = "The two new passwords don't match.";
    else if (next.size() < minLen) error = "Use at least " + std::to_string(minLen) + " characters.";
    else if (next == current) error = "That's the password you have now.";
    if (!error.empty()) return false;
    try {
        if (vault->changeMasterPassword(current, next)) return true;
        error = "That's not your current master password.";
    } catch (const std::exception& e) {
        std::cerr << "changing master password: " << e.what() << "\n";
        error = std::string("Couldn't change it: ") + e.what();
    }
    return false;
}

namespace {
template <typename T, typename F>
T boardCall(std::string& error, T onError, F&& f) {
    try {
        return f();
    } catch (const StoreUnavailable&) {
        error = "The ESP32 isn't reachable. Is it on, and is this computer on its network?";
    } catch (const std::exception& e) {
        error = e.what();
    }
    return onError;
}
}  // namespace

std::optional<std::vector<EspStore::Device>> UIManager::safeListDevices(EspStore& host, std::string& error,
                                                                        EspStore::Storage* storage) {
    return boardCall(error, std::optional<std::vector<EspStore::Device>>{},
                     [&] { return std::optional(host.devices(storage)); });
}

bool UIManager::safeRevokeDevice(EspStore& host, const std::string& name, std::string& error) {
    return boardCall(error, false, [&] { return host.revokeDevice(name), true; });
}

std::optional<EspStore::PairInvite> UIManager::safeOpenPairing(EspStore& host, std::string& error) {
    return boardCall(error, std::optional<EspStore::PairInvite>{}, [&] { return std::optional(host.openPairing()); });
}

std::string hostsDir() {
    return ConfigManager::configDir() + "/hosts";
}

const PairedHost* UIManager::pinHost() const {
    for (const PairedHost& h : hosts_)
        if (h.role == HostRole::Dedicated) return &h;
    return nullptr;
}

std::string UIManager::hostStatusText(const PairedHost& h) const {
    if (deviceOnly_) return "the only store (device-only)";
    for (const auto& s : vault->hostStatuses())
        if (s.id == h.id) switch (s.status) {
                case VaultService::SyncStatus::Ok:
                    return "synced";
                case VaultService::SyncStatus::Offline:
                    return "not reachable from here";
                case VaultService::SyncStatus::Error:
                    return "sync failed: " + s.error;
                case VaultService::SyncStatus::Disabled:
                    break;
            }
    return "not checked yet";
}

bool UIManager::safeAddHost(const std::string& address, const std::string& name, const std::string& code,
                            std::string& error, std::string* pairedId) {
    namespace fs = std::filesystem;
    auto [addr, port] = splitAddress(address);
    if (addr.empty()) return error = "Type the host's address, as it shows it.", false;
    std::string dir;
    bool replaced = false;  // re-pairing a known host: its files were overwritten, so failing loses them
    try {
        const PairedFiles f = pairWithBoard(addr, port == 443 ? kPairPort : port + 1, name, code);
        const std::string id = certFingerprint(f.serverPem);
        auto known = std::find_if(hosts_.begin(), hosts_.end(), [&](const PairedHost& h) { return h.id == id; });
        if (deviceOnly_ && !hosts_.empty() && known == hosts_.end())
            return error = "Device-only mode keeps the vault on one host only.", false;
        dir = hostsDir() + "/" + id.substr(0, 16);
        replaced = known != hosts_.end();
        saveHost(dir, f, address, HostRole::Dedicated);
        auto store = std::make_unique<EspStore>(
            EspConfig{addr, port, dir + "/server.pem", dir + "/device.pem", dir + "/device.key"});
        std::string role;
        store->devices(nullptr, &role);  // also proves the host accepts the cert it just issued
        writeHostFile(dir + "/host", "address=" + address + "\nrole=" + hostRoleName(hostRoleOf(role)) + "\n");
        if (replaced) {  // re-pairing deleted this name's PIN on the host, and the old cert is gone
            const PairedHost* pinAt = pinHost();
            if (auto pin = loadPinFile(pinFilePath()); pin && pinBelongsTo(*pin, id, pinAt ? pinAt->id : ""))
                safeRemovePin(error);
            if (!deviceOnly_) vault->removeHost(id);
            hosts_.erase(known);
        }
        PairedHost h{id, address, hostRoleOf(role), dir, store.get()};
        if (deviceOnly_) vault = std::make_unique<VaultService>(std::move(store), std::vector<SyncHost>{}, "");
        else vault->addHost({id, h.role, std::move(store)});
        hosts_.insert(std::find_if(hosts_.begin(), hosts_.end(), [&](const PairedHost& o) { return o.role > h.role; }),
                      h);
        if (pairedId) *pairedId = id;
        error.clear();
    } catch (const StoreUnavailable&) {
        error = "Paired, but the host didn't answer on port " + std::to_string(port) + ". Nothing was saved.";
    } catch (const std::exception& e) {
        error = e.what();
    }
    if (error.empty()) {
        AppConfig c = ConfigManager::getInstance().getConfig();
        if (!c.espHost.empty()) {  // the address the connector paired: it's in hosts/ now
            c.espHost.clear();
            ConfigManager::getInstance().updateConfig(c);
            ConfigManager::getInstance().saveConfig();
        }
        if (!deviceOnly_) vault->sync();
        return true;
    }
    std::error_code ec;
    if (!dir.empty() && !replaced) fs::remove_all(dir, ec);
    return false;
}

bool UIManager::safeForgetHost(std::string id, bool revokeFirst, std::string& error) {
    namespace fs = std::filesystem;
    auto it = std::find_if(hosts_.begin(), hosts_.end(), [&](const PairedHost& h) { return h.id == id; });
    if (it == hosts_.end()) return error = "No such host.", false;
    if (deviceOnly_) return error = "Device-only mode needs its host: there's no vault without it.", false;
    if (revokeFirst) try {
            for (const auto& d : it->store->devices())
                if (d.thisDevice) it->store->revokeDevice(d.name);
        } catch (const DeviceRevoked&) {  // it already refuses this computer: nothing left to revoke
        } catch (const StoreUnavailable&) {
            return error = "The host isn't reachable, so it can't revoke this computer. Forget it without revoking, "
                           "or try again on its network.", false;
        } catch (const std::exception& e) {
            return error = e.what(), false;
        }
    const PairedHost* pinAt = pinHost();
    if (auto f = loadPinFile(pinFilePath()); f && pinBelongsTo(*f, id, pinAt ? pinAt->id : "")) safeRemovePin(error);
    const std::string dir = it->dir;
    hosts_.erase(it);
    vault->removeHost(id);  // destroys its store
    std::error_code ec;
    fs::remove_all(dir, ec);
    error.clear();
    return true;
}

UIManager::BoardState UIManager::checkBoard(std::string& detail, std::string& address) {
    if (hosts_.empty()) {  // an espHost without a pairing yet; none at all: nothing to connect
        address = ConfigManager::getInstance().getConfig().espHost;
        if (address.empty()) return BoardState::Connected;
        detail = "This computer isn't paired with the host at " + address + " yet.";
        return BoardState::NotPaired;
    }
    // Most hosts are on other networks at any moment (PROTOCOL.md §6): only a refusal needs the user
    for (const PairedHost& h : hosts_) try {
            h.store->getMeta();  // any answer (a vault or none yet) means our certificate was accepted
        } catch (const StoreUnavailable&) {
        } catch (const std::exception& e) {
            address = h.address;
            detail = "The host at " + address + " refuses this computer (" + e.what() + ").";
            return BoardState::NotPaired;
        }
    return BoardState::Connected;
}

bool UIManager::safeSetHostAddress(const std::string& id, const std::string& address, std::string& error) {
    auto h = std::find_if(hosts_.begin(), hosts_.end(), [&](const PairedHost& o) { return o.id == id; });
    auto [addr, port] = splitAddress(address);
    if (h == hosts_.end() || addr.empty()) return error = "Type the address it shows now.", false;
    try {
        writeHostFile(h->dir + "/host", "address=" + address + "\nrole=" + hostRoleName(h->role) + "\n");
    } catch (const std::exception& e) {
        return error = std::string("Couldn't save it: ") + e.what(), false;
    }
    h->store->setHost(addr, port);
    h->address = address;
    return true;
}

std::string UIManager::boardAddress() const {
    for (const auto& s : vault->hostStatuses())  // the one this computer synced with, if any did
        for (const PairedHost& h : hosts_)
            if (s.status == VaultService::SyncStatus::Ok && h.id == s.id) return h.address;
    return hosts_.empty() ? ConfigManager::getInstance().getConfig().espHost : hosts_.front().address;
}

std::string UIManager::pinFilePath() {
    return ConfigManager::configDir() + "/pin.json";
}

bool UIManager::hasPin() const {
    return pinHost() && std::filesystem::exists(pinFilePath());
}

UIManager::PinResult UIManager::safeUnlockWithPin(const std::string& pin, std::string& message) {
    auto file = loadPinFile(pinFilePath());
    const PairedHost* host = pinHost();
    if (!host || !file) {
        message = "PIN unlock isn't set up here. Use your master password.";
        return PinResult::Failed;
    }
    if (!file->host.empty() && !host->id.empty() && file->host != host->id) {
        message = "This PIN belongs to another host. Use your master password.";
        return PinResult::Failed;
    }
    const std::string proof = pinProofHex(pin, base64::decode(file->salt), file->iterations);
    EspStore::PinReply reply;
    try {
        reply = host->store->tryPin(proof);
    } catch (const StoreUnavailable&) {
        message = "The ESP32 isn't reachable, and the PIN needs it. Use your master password.";
        return PinResult::Unavailable;
    } catch (const std::exception& e) {
        message = std::string(e.what()) + " Use your master password.";
        return PinResult::Failed;
    }
    std::error_code ec;
    switch (reply.result) {
        case EspStore::PinReply::Wrong:
            message = "Wrong PIN. " + std::to_string(reply.triesLeft) + (reply.triesLeft == 1 ? " try" : " tries") +
                      " left before the PIN is removed.";
            return PinResult::Wrong;
        case EspStore::PinReply::Removed:
            std::filesystem::remove(pinFilePath(), ec);
            message = "Too many wrong PINs: the board removed the PIN. Unlock with your master password; you can set a "
                      "new PIN in Settings.";
            return PinResult::Removed;
        case EspStore::PinReply::NotSet:
            std::filesystem::remove(pinFilePath(), ec);
            message = "The board has no PIN for this device anymore (revoked or re-paired). Use your master password.";
            return PinResult::Removed;
        case EspStore::PinReply::Ok:
            break;
    }
    std::string key = pinWrapKey(reply.secretHex, proof);
    bool ok = false;
    try {
        ok = vault->unlockWithPinKey(key, file->blob);
    } catch (const std::exception& e) {
        message = e.what();
    }
    vaultcrypto::wipe(key);
    if (ok) return PinResult::Unlocked;
    if (message.empty()) message = "This PIN was set up for a different vault. Use your master password.";
    return PinResult::Failed;
}

bool UIManager::safeSetPin(const std::string& masterPassword, const std::string& pin, const std::string& repeat,
                           std::string& error) {
    const PairedHost* host = pinHost();
    if (!host) error = "PIN unlock needs a dedicated host, like the ESP32 board.";
    else if (!validPin(pin)) error = "Use at least 4 digits, and only digits.";
    else if (pin != repeat) error = "The two PINs don't match.";
    else if (!vault->verifyMasterPassword(masterPassword)) error = "That's not your master password.";
    if (!error.empty()) return false;
    try {
        PinFile f;
        const std::string salt = vaultcrypto::randomBytes(16);
        f.salt = base64::encode(salt);
        f.iterations = kDefaultKdfIterations;
        f.host = host->id;
        const std::string proof = pinProofHex(pin, salt, f.iterations);
        std::string key = pinWrapKey(host->store->setPin(vaultcrypto::sha256Hex(proof)), proof);
        f.blob = vault->sealKeyForPin(key);
        vaultcrypto::wipe(key);
        savePinFile(pinFilePath(), f);
        return true;
    } catch (const StoreUnavailable&) {
        error = "The ESP32 isn't reachable. Setting a PIN needs it.";
    } catch (const std::exception& e) {
        error = std::string("Couldn't set the PIN: ") + e.what();
    }
    return false;
}

bool UIManager::safeRemovePin(std::string& error) {
    std::error_code ec;
    std::filesystem::remove(pinFilePath(), ec);
    if (std::filesystem::exists(pinFilePath())) return error = "Couldn't delete " + pinFilePath(), false;
    return true;  // the board's record opens nothing without this file, and a new PIN overwrites it
}

std::string UIManager::defaultDeviceName() {
    char buf[256] = "";
    gethostname(buf, sizeof buf - 1);
    std::string name;
    for (char ch : std::string(buf)) {
        char c = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-') name += c;
        if (c == '.') break;  // "laptop.local" -> "laptop"
    }
    while (!name.empty() && name[0] == '-') name.erase(0, 1);
    return validDeviceName(name.substr(0, 20)) ? name.substr(0, 20) : "my-computer";
}

std::string UIManager::lastSeenText(int64_t t) {
    if (t <= 0) return "not seen since the board started";
    int64_t ago = std::max<int64_t>(0, std::time(nullptr) - t);
    if (ago < 90) return "active now";
    if (ago < 3600) return "seen " + std::to_string(ago / 60) + " min ago";
    if (ago < 2 * 86400) return "seen " + std::to_string(ago / 3600) + " h ago";
    return "seen " + std::to_string(ago / 86400) + " days ago";
}

std::string UIManager::storageText(const EspStore::Storage& s) {
    if (!s.total) return "Board storage: unknown (update the board's firmware to see it)";
    const auto kb = [](uint64_t b) { return std::to_string((b + 1023) / 1024) + " KB"; };
    return "Board storage: " + kb(s.used) + " of " + kb(s.total) + " used (" + std::to_string(s.used * 100 / s.total) +
           "%), " + std::to_string(s.records) + (s.records == 1 ? " record" : " records");
}

std::string UIManager::syncStatusText() const {
    if (!ConfigManager::getInstance().getConfig().localCopy)
        return vault->lastSyncStatus() == VaultService::SyncStatus::Offline
                   ? "Device-only: ESP32 not reachable, and nothing is stored on this machine"
                   : "Device-only: reading directly from the ESP32 (nothing stored on this machine)";
    switch (vault->lastSyncStatus()) {
        case VaultService::SyncStatus::Disabled:
            return "Local vault only (no ESP32 configured)";
        case VaultService::SyncStatus::Ok:
            return "Synced with ESP32";
        case VaultService::SyncStatus::Offline:
            return "ESP32 not reachable: working locally, will sync when back";
        case VaultService::SyncStatus::Error:
            return "ESP32 sync error: " + vault->lastSyncError();
    }
    return "";
}

bool UIManager::updateCredential(const std::string& platform,
                                 const std::string& username,
                                 const std::string& password,
                                 std::optional<CipherAlg> encryptionType) {
    if (!isLoggedIn) return false;
    // Keep the entry's current cipher unless the caller picks one
    auto current = safeGetCredentials(platform);
    if (!current) return false;
    return safeAddCredential(platform, username, password, encryptionType.value_or(current->alg));
}
