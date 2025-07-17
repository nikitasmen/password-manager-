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
    auto manager = std::make_unique<CredentialsManager>(dataPath);
    if (isLoggedIn) {
        manager->login(masterPassword);
    }
    return manager;
}
