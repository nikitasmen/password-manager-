#include <iostream>
#include <string>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "config/GlobalConfig.h"
#include "gui_main.h"
#include "serve/Serve.h"
#include "tui_main.h"

/**
 * @brief Starting point of the application.
 * Options:
 *   -g, --gui, gui     : Force GUI mode
 *   -t, --tui, tui, cli: Force CLI/TUI mode
 *   -h, --help         : Show help
 * If no option is specified, the app will start with defaultUIMode from ~/.config/pwvault/config
 */
int main(int argc, char** argv) {
#ifndef _WIN32
    // Under sudo, HOME often still points at the user's home, so root would create files there that the user
    // then can't read (config, vault). A password manager has no reason to run as root anyway.
    if (geteuid() == 0) {
        std::cerr << "Don't run the password manager as root (sudo): it would create root-owned files in your\n"
                     "config folder that your own user then can't read. Run it as yourself.\n";
        return 1;
    }
#endif
    std::string mode = "";

    // Parse command line arguments
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "-g" || arg == "--gui" || arg == "gui") {
            mode = "gui";
        } else if (arg == "-t" || arg == "--tui" || arg == "tui" || arg == "cli") {
            mode = "tui";
        } else if (arg == "--serve") {
            return runServe(argc, argv);
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Password Manager\n";
            std::cout << "Usage: " << argv[0] << " [mode]\n";
            std::cout << "Modes:\n";
            std::cout << "  -g, --gui, gui     : Start in GUI mode\n";
            std::cout << "  -t, --tui, tui, cli: Start in CLI/TUI mode\n";
            std::cout << "  --serve [--role server|peer] [--port N]: host the vault for your other devices\n";
            std::cout << "  -h, --help         : Show this help\n";
            std::cout << "\nIf no mode is specified, defaultUIMode from " << ConfigManager::configFile() << " is used.\n";
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
            config.loadConfig();
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
            return guiMain();
#else
            std::cerr << "GUI mode not available in this build.\n";
            return 1;
#endif
        } else if (mode == "tui" || mode == "cli") {
#ifdef ENABLE_CLI
            return tuiMain();
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
