#include "gui.h"
#include "GuiManager.h"
#include <iostream>
#include "../config/GlobalConfig.h"

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

PasswordManagerGUI::PasswordManagerGUI() {
    try {
        // Create the GuiManager instance that will handle components
        guiManager = std::make_unique<GuiManager>(g_data_path);
    } catch (const std::exception& e) {
        std::cerr << "Error in constructor: " << e.what() << std::endl;
        exit(1);
    }
}

PasswordManagerGUI::~PasswordManagerGUI() {
    // GuiManager is cleaned up automatically when its unique_ptr is destroyed
}

void PasswordManagerGUI::show() {
    // Delegate to the GuiManager
    if (guiManager) {
        guiManager->show();
    }
}
