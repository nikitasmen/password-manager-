#include "UIManager.h"
#include "api.h"
#include <filesystem>

UIManager::UIManager(const std::string& dataPath)
    : isLoggedIn(false), dataPath(dataPath) {
    
    try {
        // Initialize the credential manager with data path
        credManager = std::make_unique<CredentialsManager>(dataPath);
        
        // Ensure data directory exists
        std::filesystem::path dir(dataPath);
        if (!std::filesystem::exists(dir)) {
            std::filesystem::create_directories(dir);
        }
    } catch (const std::exception& e) {
        // Log error but let derived class handle UI-specific error reporting
        std::cerr << "Error in UIManager constructor: " << e.what() << std::endl;
    }
}

std::unique_ptr<CredentialsManager> UIManager::getFreshCredManager() {
    if (isLoggedIn && credManager) {
        // After login, always use the existing credManager (do not create a new one)
        return nullptr; // Signal to use credManager directly
    }
    // Before login, create a new instance
    auto manager = std::make_unique<CredentialsManager>(dataPath);
    return manager;
}

bool UIManager::safeAddCredential(const std::string& platform, const std::string& username, const std::string& password, std::optional<EncryptionType> encryptionType) {
    try {
        if (!credManager) {
            std::cerr << "Error: credManager is null!" << std::endl;
            return false;
        }
        return credManager->addCredentials(platform, username, password, encryptionType);
    } catch (const std::exception& e) {
        std::cerr << "Error adding credential: " << e.what() << std::endl;
        return false;
    }
}
std::vector<std::string> UIManager::safeGetCredentials(const std::string& platform) {
    try {
        if (!credManager) {
            std::cerr << "Error: credManager is null!" << std::endl;
            return {};
        }
        return credManager->getCredentials(platform);
    } catch (const std::exception& e) {
        std::cerr << "Error getting credentials: " << e.what() << std::endl;
        return {};
    }
}
bool UIManager::safeDeleteCredential(const std::string& platform) {
    try {
        auto tempCredManager = getFreshCredManager();
        return tempCredManager->deleteCredentials(platform);
    } catch (const std::exception& e) {
        std::cerr << "Error deleting credential: " << e.what() << std::endl;
        return false;
    }
}
