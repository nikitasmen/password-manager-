#include "core/UIManagerFactory.h"
#include "config/GlobalConfig.h"
#include <iostream>
#include <exception>

int main(int argc, char** argv) {
    try {
        // Load configuration from file
        ConfigManager& configManager = ConfigManager::getInstance();
        if (!configManager.loadConfig(".config")) {
            std::cout << "Warning: Could not load configuration file. Using defaults.\n";
        }
        
        // Create UI manager for terminal interface using configured data path
        auto uiManager = UIManagerFactory::createUIManager(UIType::TERMINAL, configManager.getDataPath());
        
        // Initialize and show the UI
        uiManager->initialize();
        return uiManager->show();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occurred" << std::endl;
        return 1;
    }
}
