#include "UIManagerFactory.h"
#include "../cli/TerminalUIManager.h"
#include "../gui/GuiUIManager.h"

std::unique_ptr<UIManager> UIManagerFactory::createUIManager(UIType type, const std::string& dataPath) {
    switch (type) {
        case UIType::TERMINAL:
            return std::make_unique<TerminalUIManager>(dataPath);
        case UIType::GUI:
            return std::make_unique<GuiUIManager>(dataPath);
        default:
            throw std::runtime_error("Unknown UI type");
    }
}
