#include "UIManager.h"

#include <algorithm>
#include <unistd.h>

#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "../core/base64.h"
#include "../utils/EncryptionUtils.h"
#include "../vault/Crypto.h"
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
    ConfigManager::getInstance().saveConfig();  // keeps an address corrected in the connector
    return BoardState::Connected;
}

void UIManager::setBoardHost(const std::string& host) {
    if (!board_ || host.empty()) return;
    board_->setHost(host);
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
        for (const auto& [path, content] : out) writePrivateTmp(path, *content);
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

std::string UIManager::pinFilePath() {
    return ConfigManager::configDir() + "/pin.json";
}

bool UIManager::hasPin() const {
    return board_ && std::filesystem::exists(pinFilePath());
}

UIManager::PinResult UIManager::safeUnlockWithPin(const std::string& pin, std::string& message) {
    auto file = loadPinFile(pinFilePath());
    if (!board_ || !file) {
        message = "PIN unlock isn't set up here. Use your master password.";
        return PinResult::Failed;
    }
    const std::string proof = pinProofHex(pin, base64::decode(file->salt), file->iterations);
    EspStore::PinReply reply;
    try {
        reply = board_->tryPin(proof);
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
    if (!board_) error = "PIN unlock needs the ESP32 (espHost in the config).";
    else if (!validPin(pin)) error = "Use at least 4 digits, and only digits.";
    else if (pin != repeat) error = "The two PINs don't match.";
    else if (!vault->verifyMasterPassword(masterPassword)) error = "That's not your master password.";
    if (!error.empty()) return false;
    try {
        PinFile f;
        const std::string salt = vaultcrypto::randomBytes(16);
        f.salt = base64::encode(salt);
        f.iterations = kDefaultKdfIterations;
        const std::string proof = pinProofHex(pin, salt, f.iterations);
        std::string key = pinWrapKey(board_->setPin(vaultcrypto::sha256Hex(proof)), proof);
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
