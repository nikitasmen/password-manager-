#include "gui_main.h"
#include "tui_main.h"
#include "GlobalConfig.h"

/**
 * @brief starting point of the app.  
 * Options are -g or -t for gui or tui mode 
 * If not specified the app will start with default mode from .config
 */
int main(int argc, char** argv){ 
    std::string defaultMode  = argv[1] ? argv[1]:  ConfigManager::getInstance().getDefaultUIMode();
    if (defaultMode == "gui"){
        gui_main();
    } 
    if (defaultMode == "tui"){
        tui_main();
    }
}
