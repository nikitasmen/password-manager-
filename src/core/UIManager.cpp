#include "UIManager.h"

#include <algorithm>
#include <unistd.h>

#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "../utils/EncryptionUtils.h"
#include "../vault/EspStore.h"
#include "../vault/LocalFileStore.h"

namespace {
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
//   local-first (default): the local file, synced with the ESP32 when espHost is set
//   device-only (localCopy=false): the ESP32 as the only store, nothing written to dataPath
UIManager::UIManager(const std::string& dataPath) : isLoggedIn(false), dataPath(dataPath) {
    const AppConfig& c = ConfigManager::getInstance().getConfig();
    std::unique_ptr<IVaultStore> esp;
    if (!c.espHost.empty()) {
        auto board = std::make_unique<EspStore>(EspConfig{c.espHost, c.espPort, c.espCert, c.espClientCert, c.espClientKey});
        board_ = board.get();
        esp = std::move(board);
    }
    if (!c.localCopy) {
        if (!esp) throw std::runtime_error("localCopy=false (device-only) needs espHost in " + ConfigManager::configFile());
        vault = std::make_unique<VaultService>(std::move(esp), nullptr, "");
        return;
    }
    std::filesystem::create_directories(dataPath);
    vault = std::make_unique<VaultService>(std::make_unique<LocalFileStore>(dataPath + "/vault.json"), std::move(esp),
                                           dataPath + "/sync.json");
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

bool UIManager::safeChangeMasterPassword(const std::string& newPassword) {
    return guarded("changing master password", false, [&] {
        vault->changeMasterPassword(newPassword);
        return true;
    });
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

std::optional<std::vector<EspStore::Device>> UIManager::safeListDevices(std::string& error) {
    if (!board_) return error = "No ESP32 is set up (espHost in the config).", std::nullopt;
    return boardCall(error, std::optional<std::vector<EspStore::Device>>{}, [&] { return std::optional(board_->devices()); });
}

bool UIManager::safeRevokeDevice(const std::string& name, std::string& error) {
    if (!board_) return error = "No ESP32 is set up (espHost in the config).", false;
    return boardCall(error, false, [&] { return board_->revokeDevice(name), true; });
}

UIManager::BoardState UIManager::checkBoard(std::string& detail) {
    if (!board_) return BoardState::Connected;  // nothing configured: nothing to connect
    const AppConfig& c = ConfigManager::getInstance().getConfig();
    if (!std::filesystem::exists(c.espClientKey) || !std::filesystem::exists(c.espClientCert)) {
        detail = "This computer isn't paired with the ESP32 at " + c.espHost + " yet.";
        return BoardState::NotPaired;
    }
    try {
        board_->getMeta();  // any answer (a vault or none yet) means our certificate was accepted
    } catch (const StoreUnavailable&) {
        detail = "Can't reach the ESP32 at " + ConfigManager::getInstance().getConfig().espHost +
                 ". Is it on, and is this computer on its network?";
        return BoardState::Unreachable;
    } catch (const std::exception& e) {
        detail = "This computer isn't paired with the ESP32 (" + std::string(e.what()) + ").";
        return BoardState::NotPaired;
    }
    if (!pendingHost_.empty()) {  // a corrected address that works is worth keeping
        ConfigManager::getInstance().saveConfig();
        pendingHost_.clear();
    }
    return BoardState::Connected;
}

void UIManager::setBoardHost(const std::string& host) {
    if (!board_ || host.empty()) return;
    board_->setHost(host);
    pendingHost_ = host;
    AppConfig c = ConfigManager::getInstance().getConfig();  // so checkBoard's messages name the new address
    c.espHost = host;
    ConfigManager::getInstance().updateConfig(c);
}

bool UIManager::savePairing(const PairedFiles& files, std::string& error) {
    const AppConfig& c = ConfigManager::getInstance().getConfig();
    namespace fs = std::filesystem;
    try {
        // all three to .tmp first: cert and key must never be from different pairings
        const std::pair<std::string, const std::string*> out[] = {
            {c.espCert, &files.serverPem}, {c.espClientCert, &files.certPem}, {c.espClientKey, &files.keyPem}};
        for (const auto& [path, content] : out) {
            fs::create_directories(fs::path(path).parent_path());
            const std::string tmp = path + ".tmp";
            { std::ofstream(tmp, std::ios::trunc); }  // create it empty, restrict it, then write the secret
            fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
            std::ofstream f(tmp, std::ios::trunc | std::ios::binary);
            if (!(f << *content) || !(f.close(), f)) throw std::runtime_error("couldn't write " + tmp);
        }
        for (const auto& [path, content] : out) fs::rename(path + ".tmp", path);
    } catch (const std::exception& e) {
        error = std::string("Couldn't save the certificates: ") + e.what();
        return false;
    }
    if (!ConfigManager::getInstance().saveConfig()) {
        error = "Paired, but couldn't write " + ConfigManager::configFile() + " (is it owned by root?)";
        return false;
    }
    return true;
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
