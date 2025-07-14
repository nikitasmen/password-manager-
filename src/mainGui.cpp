#include "gui/gui.h"
#include <iostream>

int main(int argc, char** argv) {
    try {
        // Initialize FLTK
        Fl::scheme("gtk+");
        Fl::visual(FL_DOUBLE | FL_INDEX);
        
        // Create our GUI application
        PasswordManagerGUI app;
        app.show();
        
        // Enter FLTK event loop
        return Fl::run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
