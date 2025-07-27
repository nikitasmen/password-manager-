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
#include <FL/Fl_Choice.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Scroll.H>
#include <FL/fl_ask.H>
#include <sstream>
#include <memory>
#include <string>
#include <vector>
#include "../config/GlobalConfig.h"
#include "../config/MigrationHelper.h"
#include <algorithm> // for std::remove_if
#include "EncryptionUtils.h"

// Base class for text display components
class ContainerComponent : public GuiComponent {
private:
    std::vector<std::unique_ptr<GuiComponent>> children;

public:
    ContainerComponent(Fl_Group* parent, int x, int y, int w, int h)
        : GuiComponent(parent, x, y, w, h) {}

    void addChild(std::unique_ptr<GuiComponent> child) {
        children.push_back(std::move(child));
    }

    template <typename T, typename... Args>
    T* addChild(Args&&... args) {
        auto child = std::make_unique<T>(std::forward<Args>(args)...);
        T* ptr = child.get();
        children.push_back(std::move(child));
        return ptr;
    }

    void create() override {
        for (auto& child : children) {
            child->create();
        }
    }

    template <typename T>
    T* findChild() {
        for (auto& child : children) {
            T* result = dynamic_cast<T*>(child.get());
            if (result) return result;
        }
        return nullptr;
    }
};

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
        // Always fetch the current default encryption from config at creation time
        ConfigManager& config = ConfigManager::getInstance();
        EncryptionType encType = config.getDefaultEncryption();
        const char* encTypeCStr = EncryptionUtils::getDisplayName(encType);
        std::string encTypeStr = encTypeCStr ? std::string(encTypeCStr) : "Unknown";
        std::string msg;
        if (encTypeStr == "Unknown") {
            msg = "Encryption: Unknown (Check .config!)";
        } else {
            msg = "Encryption: " + encTypeStr + " (Default)";
        }
        // Debug output
        std::cerr << "[PasswordSetupComponent] encType=" << static_cast<int>(encType) << ", encTypeStr='" << encTypeStr << "'\n";
        Fl_Box* encLabel = createWidget<Fl_Box>(x + LABEL_WIDTH, y + 100, INPUT_WIDTH, INPUT_HEIGHT, "");
        encLabel->copy_label(msg.c_str());

        // Create button (moved up since we removed the dropdown)
        createButton = createWidget<Fl_Button>(centerX(BUTTON_WIDTH), y + 130, BUTTON_WIDTH, BUTTON_HEIGHT, "Create");
        CallbackHelper::setCallback(createButton, this, [this](PasswordSetupComponent* comp) {
            // Fetch the encryption type again in case config changed
            EncryptionType encType = ConfigManager::getInstance().getDefaultEncryption();
            comp->onSetup(comp->newPasswordInput->value(), 
                         comp->confirmPasswordInput->value(),
                         encType);
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
        ButtonCallback onSettings;
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
            case 1: comp->actions.onSettings(); break;
            case 2: comp->actions.onExit(); break;
            case 3: comp->actions.onAbout(); break;
        }
    }

public:
    MenuBarComponent(Fl_Group* parent, int x, int y, int w, int h,
                    ButtonCallback onAddCredential,
                    ButtonCallback onSettings,
                    ButtonCallback onExit,
                    ButtonCallback onAbout)
        : GuiComponent(parent, x, y, w, h),
          actions{onAddCredential, onSettings, onExit, onAbout},
          menuBar(nullptr) {}
    
    void create() override {
        menuBar = createWidget<Fl_Menu_Bar>(x, y, w, h);
        
        // Add menu items with standardized callback approach
        addMenuItem("File/Add Credential", 0); // Action ID 0
        addMenuItem("File/Settings", 1);       // Action ID 1
        addMenuItem("File/Exit", 2);           // Action ID 2 
        addMenuItem("Help/About", 3);          // Action ID 3
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
    Fl_Choice* encryptionChoice;

public:
    CredentialInputsComponent(Fl_Group* parent, int x, int y, int w, int h)
        : FormComponentBase(parent, x, y, w, h),
          platformInput(nullptr), usernameInput(nullptr), passwordInput(nullptr), encryptionChoice(nullptr) {}
    
    void create() override {
        platformInput = createWidget<Fl_Input>(x + LABEL_WIDTH, y, INPUT_WIDTH, INPUT_HEIGHT, "Platform:");
        usernameInput = createWidget<Fl_Input>(x + LABEL_WIDTH, y + VERTICAL_GAP, INPUT_WIDTH, INPUT_HEIGHT, "Username:");
        passwordInput = createWidget<Fl_Secret_Input>(x + LABEL_WIDTH, y + 2 * VERTICAL_GAP, INPUT_WIDTH, INPUT_HEIGHT, "Password:");
        encryptionChoice = createWidget<Fl_Choice>(x + LABEL_WIDTH, y + 3 * VERTICAL_GAP, INPUT_WIDTH, INPUT_HEIGHT, "Encryption:");
        
        // Add encryption options using helper functions
        auto availableTypes = EncryptionUtils::getAllTypes();
        for (const auto& type : availableTypes) {
            encryptionChoice->add(EncryptionUtils::getDisplayName(type));
        }
        encryptionChoice->value(EncryptionUtils::toDropdownIndex(EncryptionUtils::getDefault())); // Default encryption
    }
    
    // Methods to retrieve credential input values
    struct CredentialData {
        std::string platform;
        std::string username;
        std::string password;
        EncryptionType encryptionType;
    };
    
    CredentialData getCredentialData() const {
        return {
            platformInput ? platformInput->value() : "",
            usernameInput ? usernameInput->value() : "",
            passwordInput ? passwordInput->value() : "",
            encryptionChoice ? EncryptionUtils::fromDropdownIndex(encryptionChoice->value()) : EncryptionUtils::getDefault()
        };
    }
    
    std::string getPlatform() const { return platformInput ? platformInput->value() : ""; }
    std::string getUsername() const { return usernameInput ? usernameInput->value() : ""; }
    std::string getPassword() const { return passwordInput ? passwordInput->value() : ""; }
    EncryptionType getEncryptionType() const { 
        return encryptionChoice ? EncryptionUtils::fromDropdownIndex(encryptionChoice->value()) : EncryptionUtils::getDefault();
    }
    
    Fl_Input* getPlatformInput() const { return platformInput; }
    Fl_Input* getUsernameInput() const { return usernameInput; }
    Fl_Secret_Input* getPasswordInput() const { return passwordInput; }
    Fl_Choice* getEncryptionChoice() const { return encryptionChoice; }
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

// Component for a generic button with customizable text
class ButtonComponent : public FormComponentBase {
private:
    ButtonCallback onClick;
    std::string text;

public:
    ButtonComponent(Fl_Group* parent, int x, int y, int w, int h, const std::string& buttonText, ButtonCallback onClick)
        : FormComponentBase(parent, x, y, w, h), onClick(onClick), text(buttonText) {}
    
    void create() override {
        Fl_Button* button = createWidget<Fl_Button>(x, y, w, h, text.c_str());
        CallbackHelper::setCallback(button, this, [this](ButtonComponent* comp) {
            comp->onClick();
        });
    }
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

// Settings dialog component for configuring application settings
class SettingsDialogComponent : public FormComponentBase {
private:
    std::string masterPassword;
    const AppConfig& config;
    Fl_Scroll* scrollArea;
    Fl_Input* dataPathInput;
    Fl_Choice* defaultEncryptionChoice;
    Fl_Input* maxLoginAttemptsInput;
    Fl_Input* clipboardTimeoutInput;
    Fl_Check_Button* autoClipboardClearCheck;
    Fl_Check_Button* requirePasswordConfirmationCheck;
    Fl_Input* minPasswordLengthInput;
    Fl_Check_Button* showEncryptionInCredentialsCheck;
    Fl_Choice* defaultUIModeChoice;
    Fl_Input* lfsrTapsInput;
    Fl_Input* lfsrInitStateInput;
    
    std::function<void()> onSave;
    std::function<void()> onCancel;

public:
    SettingsDialogComponent(Fl_Group* parent, int x, int y, int w, int h, 
                            const std::string& masterPassword_in, 
                            const AppConfig& config_in,
                            std::function<void()> onSave_in = nullptr, 
                            std::function<void()> onCancel_in = nullptr)
        : FormComponentBase(parent, x, y, w, h), 
          masterPassword(masterPassword_in), 
          config(config_in), 
          onSave(onSave_in), 
          onCancel(onCancel_in) {}

    void create() override {
        const int buttonAreaHeight = 60;
        const int contentHeight = h - buttonAreaHeight;
        
        scrollArea = createWidget<Fl_Scroll>(x, y, w, contentHeight);
        scrollArea->begin();
        
        int yPos = y + 10;
        const int labelWidth = 200;
        const int fieldWidth = w - labelWidth - 40; // Adjust for padding
        const int inputX = x + labelWidth + 20;
        const int fieldHeight = 25;
        const int spacing = 35;

        // Use the passed-in config object, NOT the singleton
        auto dataPathLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Data Path:");
        dataPathInput = new Fl_Input(inputX, yPos, fieldWidth, fieldHeight);
        dataPathInput->value(config.dataPath.c_str());
        yPos += spacing;

        auto defaultEncryptionLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Default Encryption:");
        defaultEncryptionChoice = new Fl_Choice(inputX, yPos, fieldWidth, fieldHeight);
        for (const auto& type : EncryptionUtils::getAllTypes()) {
            defaultEncryptionChoice->add(EncryptionUtils::getDisplayName(type));
        }
        defaultEncryptionChoice->value(EncryptionUtils::toDropdownIndex(config.defaultEncryption));
        yPos += spacing;

        auto maxLoginAttemptsLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Max Login Attempts:");
        maxLoginAttemptsInput = new Fl_Input(inputX, yPos, fieldWidth, fieldHeight);
        maxLoginAttemptsInput->value(std::to_string(config.maxLoginAttempts).c_str());
        yPos += spacing;

        auto clipboardTimeoutLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Clipboard Timeout (s):");
        clipboardTimeoutInput = new Fl_Input(inputX, yPos, fieldWidth, fieldHeight);
        clipboardTimeoutInput->value(std::to_string(config.clipboardTimeoutSeconds).c_str());
        yPos += spacing;

        auto minPasswordLengthLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Min Password Length:");
        minPasswordLengthInput = new Fl_Input(inputX, yPos, fieldWidth, fieldHeight);
        minPasswordLengthInput->value(std::to_string(config.minPasswordLength).c_str());
        yPos += spacing;

        auto defaultUIModeLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Default UI Mode:");
        defaultUIModeChoice = new Fl_Choice(inputX, yPos, fieldWidth, fieldHeight);
        defaultUIModeChoice->add("CLI");
        defaultUIModeChoice->add("GUI");
        defaultUIModeChoice->add("auto"); // should be lowercase 'auto'
        // Correctly set the default UI mode choice
        if (config.defaultUIMode == "CLI") {
            defaultUIModeChoice->value(0);
        } else if (config.defaultUIMode == "GUI") {
            defaultUIModeChoice->value(1);
        } else {
            defaultUIModeChoice->value(2);
        }
        yPos += spacing;

        autoClipboardClearCheck = new Fl_Check_Button(x + 10, yPos, w - 20, fieldHeight, "Auto-clear Clipboard");
        autoClipboardClearCheck->value(config.autoClipboardClear);
        yPos += spacing;

        requirePasswordConfirmationCheck = new Fl_Check_Button(x + 10, yPos, w - 20, fieldHeight, "Require Password Confirmation");
        requirePasswordConfirmationCheck->value(config.requirePasswordConfirmation);
        yPos += spacing;

        showEncryptionInCredentialsCheck = new Fl_Check_Button(x + 10, yPos, w - 20, fieldHeight, "Show Encryption in Credentials");
        showEncryptionInCredentialsCheck->value(config.showEncryptionInCredentials);
        yPos += spacing;

        auto lfsrTapsLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "LFSR Taps (comma-sep):");
        lfsrTapsInput = new Fl_Input(inputX, yPos, fieldWidth, fieldHeight);
        lfsrTapsInput->value(vectorToString(config.lfsrTaps).c_str());
        yPos += spacing;
        
        auto lfsrInitStateLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "LFSR Init State (comma-sep):");
        lfsrInitStateInput = new Fl_Input(inputX, yPos, fieldWidth, fieldHeight);
        lfsrInitStateInput->value(vectorToString(config.lfsrInitState).c_str());
        yPos += spacing;

        scrollArea->end();
        
        int buttonY = y + h - 50;
        Fl_Button* saveButton = createWidget<Fl_Button>(x + w/2 - 120, buttonY, 100, 30, "Save");
        Fl_Button* cancelButton = createWidget<Fl_Button>(x + w/2 + 20, buttonY, 100, 30, "Cancel");
        
        CallbackHelper::setCallback(saveButton, this, [this](SettingsDialogComponent* comp) { comp->saveSettings(); });
        CallbackHelper::setCallback(cancelButton, this, [this](SettingsDialogComponent* comp) { if (onCancel) onCancel(); });

        if (parent) parent->redraw();
    }

private:
    std::string vectorToString(const std::vector<int>& vec) {
        std::stringstream ss;
        for (size_t i = 0; i < vec.size(); ++i) {
            if (i > 0) ss << ",";
            ss << vec[i];
        }
        return ss.str();
    }

    std::vector<int> stringToVector(const std::string& s) {
        std::vector<int> vec;
        if (s.empty()) return vec;
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, ',')) {
            item.erase(std::remove_if(item.begin(), item.end(), isspace), item.end());
            if (!item.empty()) {
                try {
                    vec.push_back(std::stoi(item));
                } catch (const std::exception& e) {
                    // ignore invalid numbers
                }
            }
        }
        return vec;
    }

    void saveSettings() {
        // Collect all settings from the UI
        AppConfig newConfig;
        try {
            newConfig.dataPath = dataPathInput->value();
            newConfig.defaultEncryption = EncryptionUtils::fromDropdownIndex(defaultEncryptionChoice->value());
            newConfig.maxLoginAttempts = std::stoi(maxLoginAttemptsInput->value());
            newConfig.clipboardTimeoutSeconds = std::stoi(clipboardTimeoutInput->value());
            newConfig.autoClipboardClear = autoClipboardClearCheck->value();
            newConfig.requirePasswordConfirmation = requirePasswordConfirmationCheck->value();
            newConfig.minPasswordLength = std::stoi(minPasswordLengthInput->value());
            newConfig.showEncryptionInCredentials = showEncryptionInCredentialsCheck->value();
            newConfig.defaultUIMode = defaultUIModeChoice->menu()[defaultUIModeChoice->value()].label();

            newConfig.lfsrTaps = stringToVector(lfsrTapsInput->value());
            newConfig.lfsrInitState = stringToVector(lfsrInitStateInput->value());
        } catch (const std::invalid_argument& ia) {
            fl_alert("Invalid number format in one of the fields.");
            return;
        } catch (const std::out_of_range& oor) {
            fl_alert("Number out of range in one of the fields.");
            return;
        }

        // Get current config to compare against
        const AppConfig& oldConfig = ConfigManager::getInstance().getConfig();

        // Apply settings and perform migrations if necessary
        bool success = MigrationHelper::getInstance().applySettingsFromConfig(oldConfig, newConfig, masterPassword);

        if (success) {
            fl_alert("Settings saved and applied successfully!");
            if (onSave) {
                onSave(); // This will close the dialog
            }
        } else {
            fl_alert("Failed to apply new settings. The password might be incorrect or a migration failed. Check the console for details.");
            // Do not close the dialog on failure
        }
    }
};

#endif // GUI_COMPONENTS_H
