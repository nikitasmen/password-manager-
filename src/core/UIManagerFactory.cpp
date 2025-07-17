#include "UIManagerFactory.h"

// These includes will be conditionally compiled based on build configuration
#ifdef ENABLE_CLI
#include "../cli/TerminalUIManager.h"
#endif

#ifdef ENABLE_GUI
#include "../gui/GuiUIManager.h"
#endif

std::unique_ptr<UIManager> UIManagerFactory::createUIManager(UIType type, const std::string& dataPath) {
    switch (type) {
#ifdef ENABLE_CLI
        case UIType::TERMINAL:
            return std::make_unique<TerminalUIManager>(dataPath);
#endif
#ifdef ENABLE_GUI
        case UIType::GUI:
            return std::make_unique<GuiUIManager>(dataPath);
#endif
        default:
            throw std::runtime_error("Unknown or unsupported UI type");
    }
}
