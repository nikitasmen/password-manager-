#include "gui/gui.h"
#include <iostream>
#include "../GlobalConfig.h"
#include <exception>
#include <filesystem>

int main(int argc, char** argv) {
    try {
        
        // Create data directory if it doesn't exist
        std::filesystem::path dir(data_path);
        if (!std::filesystem::exists(dir)) {
            std::filesystem::create_directories(dir);
            std::cout << "Created data directory: " << data_path << std::endl;
        }
        
        // Initialize FLTK with error handling
        if (!Fl::scheme("gtk+")) {
            std::cerr << "Warning: Could not set GTK+ scheme" << std::endl;
        }
        if (!Fl::visual(FL_DOUBLE | FL_INDEX)) {
            std::cerr << "Warning: Could not set requested visual" << std::endl;
        }
        
        // Create our GUI application
        PasswordManagerGUI app;
        app.show();
        
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
