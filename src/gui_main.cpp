#include "gui/gui.h"
#include <iostream>
#include "config/GlobalConfig.h"
#include <exception>
#include <filesystem>

int main(int argc, char** argv) {
    try {
        // Print data path for debugging
        std::cout << "GUI application starting" << std::endl;
        std::cout << "Using data path: " << data_path << std::endl;
        
        // Create data directory if it doesn't exist
        std::filesystem::path dir(data_path);
        if (!std::filesystem::exists(dir)) {
            std::cout << "Creating data directory: " << data_path << std::endl;
            std::filesystem::create_directories(dir);
        }
        
        // Initialize FLTK with more lenient error handling
        Fl::scheme("gtk+");
        Fl::visual(FL_DOUBLE | FL_RGB);
        
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
