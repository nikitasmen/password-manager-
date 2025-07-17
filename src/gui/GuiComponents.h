#ifndef GUI_COMPONENTS_H
#define GUI_COMPONENTS_H

#include "GuiComponent.h"
#include <FL/Fl_Box.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Menu_Bar.H>
#include <sstream>
#include <memory>

// Base class for text display components
class TextComponentBase : public GuiComponent {
protected:
    std::string text;

public:
    TextComponentBase(Fl_Group* parent, int x, int y, int w, int h, const std::string& text)
        : GuiComponent(parent, x, y, w, h), text(text) {}
        
    virtual void setText(const std::string& newText) {
        text = newText;
    }
    
    const std::string& getText() const { return text; }
};

// Component for displaying a title
class TitleComponent : public TextComponentBase {
private:
    int fontSize;

public:
    TitleComponent(Fl_Group* parent, int x, int y, int w, int h, 
                  const std::string& title, int fontSize = 20)
        : TextComponentBase(parent, x, y, w, h, title), fontSize(fontSize) {}
    
    void create() override {
        Fl_Box* titleBox = createWidget<Fl_Box>(x, y, w, h, text.c_str());
        titleBox->labelsize(fontSize);
    }
};

// Component for displaying a descriptive text
class DescriptionComponent : public TextComponentBase {
public:
    DescriptionComponent(Fl_Group* parent, int x, int y, int w, int h, const std::string& text)
        : TextComponentBase(parent, x, y, w, h, text) {}
    
    void create() override {
        createWidget<Fl_Box>(x, y, w, h, text.c_str());
    }
};

// Base component for forms with a callback
class FormComponentBase : public GuiComponent {
protected:
    // Common button dimensions
    static constexpr int BUTTON_WIDTH = 100;
    static constexpr int BUTTON_HEIGHT = 30;
    static constexpr int INPUT_HEIGHT = 30;

public:
    FormComponentBase(Fl_Group* parent, int x, int y, int w, int h)
        : GuiComponent(parent, x, y, w, h) {}
    
    // Helper method to center a button
    int centerX(int buttonWidth) const {
        return x + (w/2) - (buttonWidth/2);
    }
};

// Component for login form
class LoginFormComponent : public FormComponentBase {
private:
    TextCallback onLogin;
    Fl_Secret_Input* passwordInput;
    Fl_Button* loginButton;

public:
    LoginFormComponent(Fl_Group* parent, int x, int y, int w, int h, TextCallback onLogin)
        : FormComponentBase(parent, x, y, w, h), onLogin(onLogin), 
          passwordInput(nullptr), loginButton(nullptr) {}
    
    void create() override {
        // Create password input
        passwordInput = createWidget<Fl_Secret_Input>(x + 50, y, w - 100, INPUT_HEIGHT, "Master Password:");
        
        // Create login button
        loginButton = createWidget<Fl_Button>(centerX(BUTTON_WIDTH), y + 60, BUTTON_WIDTH, BUTTON_HEIGHT, "Login");
        CallbackHelper::setCallback(loginButton, this, [this](LoginFormComponent* comp) {
            comp->onLogin(comp->passwordInput->value());
        });
    }
    
    Fl_Secret_Input* getPasswordInput() const { return passwordInput; }
    Fl_Button* getLoginButton() const { return loginButton; }
};

// Component for password setup form
class PasswordSetupComponent : public FormComponentBase {
private:
    PasswordCallback onSetup;
    Fl_Secret_Input* newPasswordInput;
    Fl_Secret_Input* confirmPasswordInput;
    Fl_Button* createButton;
    
    static constexpr int INPUT_WIDTH = 200;
    static constexpr int LABEL_WIDTH = 180;

public:
    PasswordSetupComponent(Fl_Group* parent, int x, int y, int w, int h, PasswordCallback onSetup)
        : FormComponentBase(parent, x, y, w, h), onSetup(onSetup),
          newPasswordInput(nullptr), confirmPasswordInput(nullptr), createButton(nullptr) {}
    
    void create() override {
        // Create password inputs
        newPasswordInput = createWidget<Fl_Secret_Input>(x + LABEL_WIDTH, y, INPUT_WIDTH, INPUT_HEIGHT, "New Master Password:");
        confirmPasswordInput = createWidget<Fl_Secret_Input>(x + LABEL_WIDTH, y + 50, INPUT_WIDTH, INPUT_HEIGHT, "Confirm Password:");
        
        // Create button
        createButton = createWidget<Fl_Button>(centerX(BUTTON_WIDTH), y + 100, BUTTON_WIDTH, BUTTON_HEIGHT, "Create");
        CallbackHelper::setCallback(createButton, this, [this](PasswordSetupComponent* comp) {
            comp->onSetup(comp->newPasswordInput->value(), comp->confirmPasswordInput->value());
        });
    }
    
    Fl_Secret_Input* getNewPasswordInput() const { return newPasswordInput; }
    Fl_Secret_Input* getConfirmPasswordInput() const { return confirmPasswordInput; }
    Fl_Button* getCreateButton() const { return createButton; }
};

// Component for menu bar
class MenuBarComponent : public GuiComponent {
private:
    struct MenuActions {
        ButtonCallback onAddCredential;
        ButtonCallback onExit;
        ButtonCallback onAbout;
    };
    
    MenuActions actions;
    Fl_Menu_Bar* menuBar;
    std::vector<void*> callbackData; // Store pointers to allocated callback data for cleanup

    // Generic menu callback using the component's actions
    static void menuCallback(Fl_Widget*, void* data) {
        auto* callbackInfo = static_cast<std::pair<MenuBarComponent*, int>*>(data);
        MenuBarComponent* comp = callbackInfo->first;
        int actionId = callbackInfo->second;
        
        switch(actionId) {
            case 0: comp->actions.onAddCredential(); break;
            case 1: comp->actions.onExit(); break;
            case 2: comp->actions.onAbout(); break;
        }
    }

public:
    MenuBarComponent(Fl_Group* parent, int x, int y, int w, int h,
                    ButtonCallback onAddCredential,
                    ButtonCallback onExit,
                    ButtonCallback onAbout)
        : GuiComponent(parent, x, y, w, h),
          actions{onAddCredential, onExit, onAbout},
          menuBar(nullptr) {}
    
    void create() override {
        menuBar = createWidget<Fl_Menu_Bar>(x, y, w, h);
        
        // Add menu items with standardized callback approach
        addMenuItem("File/Add Credential", 0); // Action ID 0
        addMenuItem("File/Exit", 1);          // Action ID 1 
        addMenuItem("Help/About", 2);         // Action ID 2
    }
    
    // Helper method to add menu items with consistent handling
    void addMenuItem(const char* path, int actionId) {
        auto* callbackInfo = new std::pair<MenuBarComponent*, int>(this, actionId);
        callbackData.push_back(callbackInfo); // Store for cleanup
        menuBar->add(path, 0, menuCallback, callbackInfo);
    }
    
    Fl_Menu_Bar* getMenuBar() const { return menuBar; }
    
    // Clean up allocated callback data
    void cleanup() override {
        for (void* data : callbackData) {
            delete static_cast<std::pair<MenuBarComponent*, int>*>(data);
        }
        callbackData.clear();
        GuiComponent::cleanup();
    }
};

// Base component for text displays using buffer
class BufferedTextDisplayBase : public GuiComponent {
protected:
    Fl_Text_Display* display;
    Fl_Text_Buffer* buffer;
    std::string label;

public:
    BufferedTextDisplayBase(Fl_Group* parent, int x, int y, int w, int h, const std::string& label = "")
        : GuiComponent(parent, x, y, w, h), display(nullptr), buffer(nullptr), label(label) {}
    
    virtual void create() override {
        buffer = new Fl_Text_Buffer();
        
        // Create display with or without label based on provided label
        if (!label.empty()) {
            display = createWidget<Fl_Text_Display>(x, y, w, h, label.c_str());
        } else {
            display = createWidget<Fl_Text_Display>(x, y, w, h);
        }
        
        display->buffer(buffer);
    }
    
    void setText(const std::string& text) {
        if (buffer) {
            buffer->text(text.c_str());
        }
    }
    
    void cleanup() override {
        if (display && buffer) {
            display->buffer(nullptr);
        }
        if (buffer) {
            delete buffer;
            buffer = nullptr;
        }
        GuiComponent::cleanup();
    }
    
    Fl_Text_Display* getDisplay() const { return display; }
    Fl_Text_Buffer* getBuffer() const { return buffer; }
};

// Component for platforms display
class PlatformsDisplayComponent : public BufferedTextDisplayBase {
public:
    PlatformsDisplayComponent(Fl_Group* parent, int x, int y, int w, int h)
        : BufferedTextDisplayBase(parent, x, y, w, h, "Stored Platforms:") {}
    
    void create() override {
        BufferedTextDisplayBase::create();
    }
};

// Component for action buttons
class ActionButtonsComponent : public FormComponentBase {
private:
    static constexpr int BUTTON_WIDTH = 100;
    static constexpr int BUTTON_HEIGHT = 25;
    static constexpr int BUTTON_GAP = 20;
    
    ButtonCallback onView;
    ButtonCallback onDelete;

public:
    ActionButtonsComponent(Fl_Group* parent, int x, int y, int w, int h,
                          ButtonCallback onView,
                          ButtonCallback onDelete)
        : FormComponentBase(parent, x, y, w, h), onView(onView), onDelete(onDelete) {}
    
    void create() override {
        // Create view button
        Fl_Button* viewButton = createWidget<Fl_Button>(x, y, BUTTON_WIDTH, BUTTON_HEIGHT, "View");
        CallbackHelper::setCallback(viewButton, this, [this](ActionButtonsComponent* comp) {
            comp->onView();
        });
        
        // Create delete button
        Fl_Button* deleteButton = createWidget<Fl_Button>(
            x + BUTTON_WIDTH + BUTTON_GAP, 
            y, 
            BUTTON_WIDTH, 
            BUTTON_HEIGHT, 
            "Delete"
        );
        CallbackHelper::setCallback(deleteButton, this, [this](ActionButtonsComponent* comp) {
            comp->onDelete();
        });
    }
};

// Component for credential inputs
class CredentialInputsComponent : public FormComponentBase {
private:
    static constexpr int LABEL_WIDTH = 150;
    static constexpr int INPUT_WIDTH = 200;
    static constexpr int VERTICAL_GAP = 50;
    
    Fl_Input* platformInput;
    Fl_Input* usernameInput;
    Fl_Secret_Input* passwordInput;

public:
    CredentialInputsComponent(Fl_Group* parent, int x, int y, int w, int h)
        : FormComponentBase(parent, x, y, w, h),
          platformInput(nullptr), usernameInput(nullptr), passwordInput(nullptr) {}
    
    void create() override {
        platformInput = createWidget<Fl_Input>(x + LABEL_WIDTH, y, INPUT_WIDTH, INPUT_HEIGHT, "Platform:");
        usernameInput = createWidget<Fl_Input>(x + LABEL_WIDTH, y + VERTICAL_GAP, INPUT_WIDTH, INPUT_HEIGHT, "Username:");
        passwordInput = createWidget<Fl_Secret_Input>(x + LABEL_WIDTH, y + 2 * VERTICAL_GAP, INPUT_WIDTH, INPUT_HEIGHT, "Password:");
    }
    
    // Methods to retrieve credential input values
    struct CredentialData {
        std::string platform;
        std::string username;
        std::string password;
    };
    
    CredentialData getCredentialData() const {
        return {
            platformInput ? platformInput->value() : "",
            usernameInput ? usernameInput->value() : "",
            passwordInput ? passwordInput->value() : ""
        };
    }
    
    std::string getPlatform() const { return platformInput ? platformInput->value() : ""; }
    std::string getUsername() const { return usernameInput ? usernameInput->value() : ""; }
    std::string getPassword() const { return passwordInput ? passwordInput->value() : ""; }
    
    Fl_Input* getPlatformInput() const { return platformInput; }
    Fl_Input* getUsernameInput() const { return usernameInput; }
    Fl_Secret_Input* getPasswordInput() const { return passwordInput; }
};

// Dialog button layout configurations
struct DialogButtonConfig {
    int buttonWidth = 80;
    int buttonHeight = 30;
    int buttonGap = 40;
};

// Component for credential dialog buttons
class CredentialDialogButtonsComponent : public FormComponentBase {
private:
    ButtonCallback onSave;
    ButtonCallback onCancel;
    DialogButtonConfig config;

public:
    CredentialDialogButtonsComponent(Fl_Group* parent, int x, int y, int w, int h,
                                    ButtonCallback onSave,
                                    ButtonCallback onCancel,
                                    const DialogButtonConfig& config = DialogButtonConfig())
        : FormComponentBase(parent, x, y, w, h), onSave(onSave), onCancel(onCancel), config(config) {}
    
    void create() override {
        // Position buttons with equal spacing
        int totalWidth = 2 * config.buttonWidth + config.buttonGap;
        int startX = centerX(totalWidth);
        
        // Create buttons
        Fl_Button* saveButton = createWidget<Fl_Button>(startX, y, config.buttonWidth, config.buttonHeight, "Save");
        CallbackHelper::setCallback(saveButton, this, [this](CredentialDialogButtonsComponent* comp) {
            comp->onSave();
        });
        
        Fl_Button* cancelButton = createWidget<Fl_Button>(
            startX + config.buttonWidth + config.buttonGap, 
            y, 
            config.buttonWidth, 
            config.buttonHeight, 
            "Cancel"
        );
        CallbackHelper::setCallback(cancelButton, this, [this](CredentialDialogButtonsComponent* comp) {
            comp->onCancel();
        });
    }
};

// Component for credential display
class CredentialDisplayComponent : public BufferedTextDisplayBase {
public:
    CredentialDisplayComponent(Fl_Group* parent, int x, int y, int w, int h)
        : BufferedTextDisplayBase(parent, x, y, w, h) {}
    
    // Base class implementation already handles everything we need
};

// Component for a close button
class CloseButtonComponent : public FormComponentBase {
private:
    ButtonCallback onClose;

public:
    CloseButtonComponent(Fl_Group* parent, int x, int y, int w, int h, ButtonCallback onClose)
        : FormComponentBase(parent, x, y, w, h), onClose(onClose) {}
    
    void create() override {
        Fl_Button* closeButton = createWidget<Fl_Button>(x, y, w, h, "Close");
        CallbackHelper::setCallback(closeButton, this, [this](CloseButtonComponent* comp) {
            comp->onClose();
        });
    }
};

// A container component that doesn't create any widgets itself
// Used as a parent for other components to create composite UIs
class ContainerComponent : public GuiComponent {
public:
    ContainerComponent(Fl_Group* parent, int x, int y, int w, int h)
        : GuiComponent(parent, x, y, w, h) {}
    
    // Create all child components
    void create() override {
        // Create all child components
        for (auto& child : children) {
            child->create();
        }
    }
};

#endif // GUI_COMPONENTS_H
