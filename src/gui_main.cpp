#include "core/UIManagerFactory.h"
#include <iostream>
#include "config/GlobalConfig.h"
#include <exception>
#include <filesystem>
#include <FL/Fl.H>

int main(int argc, char** argv) {
    try {
        // Create data directory if it doesn't exist
        std::filesystem::path dir(g_data_path);
        if (!std::filesystem::exists(dir)) {
            std::filesystem::create_directories(dir);
        }
        
        // Initialize FLTK with more lenient error handling
        Fl::scheme("gtk+");
        Fl::visual(FL_DOUBLE | FL_RGB);
        
        // Create UI manager for graphical interface
        auto uiManager = UIManagerFactory::createUIManager(UIType::GUI, g_data_path);
        
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
