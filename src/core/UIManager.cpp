#include "UIManager.h"

#include <filesystem>
#include <iostream>

#include "../utils/EncryptionUtils.h"
#include "../vault/VaultFactory.h"

// Throws if the vault can't be set up (e.g. unwritable dataPath): tui_main/gui_main report it and exit,
// so no UI code ever runs with a null vault.
UIManager::UIManager(const std::string& dataPath) : isLoggedIn(false), dataPath(dataPath) {
    std::filesystem::create_directories(dataPath);
    AppConfig config = ConfigManager::getInstance().getConfig();
    config.dataPath = dataPath;
    vault = makeVaultService(config);
}

bool UIManager::safeAddCredential(const std::string& platform,
                                  const std::string& username,
                                  const std::string& password,
                                  std::optional<CipherAlg> encryptionType) {
    try {
        vault->put({platform, username, password, encryptionType.value_or(encryption_utils::getDefault())});
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error adding credential: " << e.what() << std::endl;
        return false;
    }
}

std::optional<Credential> UIManager::safeGetCredentials(const std::string& platform) {
    try {
        return vault->get(platform);
    } catch (const std::exception& e) {
        std::cerr << "Error getting credentials: " << e.what() << std::endl;
        return std::nullopt;
    }
}

bool UIManager::safeDeleteCredential(const std::string& platform) {
    try {
        return vault->remove(platform);
    } catch (const std::exception& e) {
        std::cerr << "Error deleting credential: " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::string> UIManager::safeGetPlatforms() {
    try {
        return vault->platforms();
    } catch (const std::exception& e) {
        std::cerr << "Error listing platforms: " << e.what() << std::endl;
        return {};
    }
}

bool UIManager::safeChangeMasterPassword(const std::string& newPassword) {
    try {
        vault->changeMasterPassword(newPassword);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error changing master password: " << e.what() << std::endl;
        return false;
    }
}

std::string UIManager::syncStatusText() const {
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
