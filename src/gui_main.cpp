#include "gui_main.h"

#include <FL/Fl.H>

#include <exception>
#include <filesystem>
#include <iostream>

#include "config/GlobalConfig.h"
#include "core/UIManagerFactory.h"

int guiMain() {
    try {
        // Load configuration from file
        ConfigManager& configManager = ConfigManager::getInstance();
        if (!configManager.loadConfig(".config")) {
            std::cout << "Warning: Could not load configuration file. Using defaults.\n";
        }

        // Create data directory if it doesn't exist
        std::filesystem::path dir(configManager.getDataPath());
        if (!std::filesystem::exists(dir)) {
            std::filesystem::create_directories(dir);
        }

        // Initialize FLTK with more lenient error handling
        Fl::scheme("gtk+");
        Fl::visual(FL_DOUBLE | FL_RGB);

        // Create UI manager for graphical interface using configured data path
        auto uiManager = UIManagerFactory::createUIManager(UIType::GUI, configManager.getDataPath());

        // Initialize and show the UI
        uiManager->initialize();
        uiManager->show();

        // Enter FLTK event loop
        return Fl::run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occurred" << std::endl;
        return 1;
    }
}
