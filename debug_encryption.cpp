#include "src/config/GlobalConfig.h"
#include <iostream>

int main() {
    std::cout << "Initial g_encryption_type: " << static_cast<int>(g_encryption_type) << std::endl;
    
    ConfigManager& configManager = ConfigManager::getInstance();
    std::cout << "After getInstance, g_encryption_type: " << static_cast<int>(g_encryption_type) << std::endl;
    
    if (configManager.loadConfig(".config")) {
        std::cout << "Config loaded successfully" << std::endl;
        std::cout << "After loadConfig, g_encryption_type: " << static_cast<int>(g_encryption_type) << std::endl;
        std::cout << "Config defaultEncryption: " << static_cast<int>(configManager.getDefaultEncryption()) << std::endl;
    } else {
        std::cout << "Failed to load config" << std::endl;
    }
    
    return 0;
}
