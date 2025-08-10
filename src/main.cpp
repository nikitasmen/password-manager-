#include "gui_main.h"
#include "tui_main.h"
#include "config/GlobalConfig.h"
#include <iostream>
#include <string>

/**
 * @brief Starting point of the application.  
 * Options:
 *   -g, --gui, gui     : Force GUI mode
 *   -t, --tui, tui, cli: Force CLI/TUI mode
 *   -h, --help         : Show help
 * If no option is specified, the app will start with default mode from .config
 */
int main(int argc, char** argv) {
    std::string mode = "";
    
    // Parse command line arguments
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-g" || arg == "--gui" || arg == "gui") {
            mode = "gui";
        } else if (arg == "-t" || arg == "--tui" || arg == "tui" || arg == "cli") {
            mode = "tui";
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Password Manager\n";
            std::cout << "Usage: " << argv[0] << " [mode]\n";
            std::cout << "Modes:\n";
            std::cout << "  -g, --gui, gui     : Start in GUI mode\n";
            std::cout << "  -t, --tui, tui, cli: Start in CLI/TUI mode\n";
            std::cout << "  -h, --help         : Show this help\n";
            std::cout << "\nIf no mode is specified, the default from .config file will be used.\n";
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            std::cerr << "Use --help for usage information.\n";
            return 1;
        }
    }
    
    // If no mode specified, get default from config
    if (mode.empty()) {
        try {
            ConfigManager& config = ConfigManager::getInstance();
            config.loadConfig(".config");
            mode = config.getDefaultUIMode();
            
            // Handle "auto" mode by defaulting to GUI if available, otherwise CLI
            if (mode == "auto") {
#ifdef ENABLE_GUI
                mode = "gui";
#else
                mode = "tui";
#endif
            }
        } catch (const std::exception& e) {
            std::cerr << "Error loading config: " << e.what() << "\n";
            std::cerr << "Defaulting to CLI mode.\n";
            mode = "tui";
        }
    }
    
    // Launch the appropriate interface
    try {
        if (mode == "gui") {
#ifdef ENABLE_GUI
            return gui_main();
#else
            std::cerr << "GUI mode not available in this build.\n";
            return 1;
#endif
        } else if (mode == "tui" || mode == "cli") {
#ifdef ENABLE_CLI
            return tui_main();
#else
            std::cerr << "CLI mode not available in this build.\n";
            return 1;
#endif
        } else {
            std::cerr << "Invalid mode: " << mode << "\n";
            std::cerr << "Valid modes are 'gui' and 'tui'.\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error starting application: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown error starting application" << std::endl;
        return 1;
    }
}
