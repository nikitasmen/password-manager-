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
