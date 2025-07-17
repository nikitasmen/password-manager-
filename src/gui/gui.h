#ifndef GUI_H
#define GUI_H

#include <memory>

// Forward declaration
class GuiManager;

class PasswordManagerGUI {
private:
    // GuiManager handles all component orchestration
    std::unique_ptr<GuiManager> guiManager;

public:
    PasswordManagerGUI();
    ~PasswordManagerGUI();
    
    // Public interface methods - delegate to GuiManager
    void show();
};

#endif // GUI_H
