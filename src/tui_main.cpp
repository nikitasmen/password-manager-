#include "../core/UIManagerFactory.h"
#include "../config/GlobalConfig.h"
#include <iostream>
#include <exception>

int main(int argc, char** argv) {
    try {
        // Create UI manager for terminal interface
        auto uiManager = UIManagerFactory::createUIManager(UIType::TERMINAL, g_data_path);
        
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
