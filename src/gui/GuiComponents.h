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
#include "../config/GlobalConfig.h"

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
        
        // Add information about encryption (no user choice)
        createWidget<Fl_Box>(x + LABEL_WIDTH, y + 100, INPUT_WIDTH, INPUT_HEIGHT, "Encryption: AES-256 with LFSR (Strongest)");
        
        // Create button (moved up since we removed the dropdown)
        createButton = createWidget<Fl_Button>(centerX(BUTTON_WIDTH), y + 130, BUTTON_WIDTH, BUTTON_HEIGHT, "Create");
        CallbackHelper::setCallback(createButton, this, [this](PasswordSetupComponent* comp) {
            // Always use dual AES+LFSR encryption (strongest security)
            EncryptionType encType = EncryptionType::AES_LFSR;
            
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
                           std::function<void()> onSave = nullptr,
                           std::function<void()> onCancel = nullptr)
        : FormComponentBase(parent, x, y, w, h), onSave(onSave), onCancel(onCancel) {}
    
    void create() override {
        // Create scroll area that takes most of the dialog space, leaving room for buttons
        const int buttonAreaHeight = 60;
        scrollArea = createWidget<Fl_Scroll>(x, y, w, h - buttonAreaHeight);
        scrollArea->begin();
        
        int yPos = y + 20;
        const int labelWidth = 180;
        const int fieldWidth = 200;
        const int fieldHeight = 25;
        const int spacing = 35;
        
        // Load current configuration
        ConfigManager& config = ConfigManager::getInstance();
        
        // Add a title first to verify the dialog is working
        auto titleBox = new Fl_Box(x + 10, yPos, w - 30, 30, "Application Settings");
        titleBox->labelfont(FL_BOLD);
        titleBox->labelsize(16);
        titleBox->align(FL_ALIGN_CENTER);
        yPos += 40;
        
        // Data Path
        auto dataPathLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Data Path:");
        dataPathLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        dataPathInput = new Fl_Input(x + labelWidth + 20, yPos, fieldWidth, fieldHeight);
        dataPathInput->value(config.getDataPath().c_str());
        yPos += spacing;
        
        // Default Encryption
        auto encryptionLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Default Encryption:");
        encryptionLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        defaultEncryptionChoice = new Fl_Choice(x + labelWidth + 20, yPos, fieldWidth, fieldHeight);
        defaultEncryptionChoice->add("AES");
        defaultEncryptionChoice->add("LFSR");
        defaultEncryptionChoice->add("AES+LFSR");
        defaultEncryptionChoice->value(static_cast<int>(config.getDefaultEncryption()));
        yPos += spacing;
        
        // Max Login Attempts
        auto attemptsLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Max Login Attempts:");
        attemptsLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        maxLoginAttemptsInput = new Fl_Input(x + labelWidth + 20, yPos, fieldWidth, fieldHeight);
        maxLoginAttemptsInput->value(std::to_string(config.getMaxLoginAttempts()).c_str());
        yPos += spacing;
        
        // Clipboard Timeout
        auto clipboardLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Clipboard Timeout (sec):");
        clipboardLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        clipboardTimeoutInput = new Fl_Input(x + labelWidth + 20, yPos, fieldWidth, fieldHeight);
        clipboardTimeoutInput->value(std::to_string(config.getClipboardTimeoutSeconds()).c_str());
        yPos += spacing;
        
        // Auto Clipboard Clear
        autoClipboardClearCheck = new Fl_Check_Button(x + 10, yPos, w - 30, fieldHeight, "Auto Clear Clipboard");
        autoClipboardClearCheck->value(config.getAutoClipboardClear() ? 1 : 0);
        yPos += spacing;
        
        // Require Password Confirmation
        requirePasswordConfirmationCheck = new Fl_Check_Button(x + 10, yPos, w - 30, fieldHeight, "Require Password Confirmation");
        requirePasswordConfirmationCheck->value(config.getRequirePasswordConfirmation() ? 1 : 0);
        yPos += spacing;
        
        // Min Password Length
        auto minLengthLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Min Password Length:");
        minLengthLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        minPasswordLengthInput = new Fl_Input(x + labelWidth + 20, yPos, fieldWidth, fieldHeight);
        minPasswordLengthInput->value(std::to_string(config.getMinPasswordLength()).c_str());
        yPos += spacing;
        
        // Show Encryption in Credentials
        showEncryptionInCredentialsCheck = new Fl_Check_Button(x + 10, yPos, w - 30, fieldHeight, "Show Encryption Type in Credentials");
        showEncryptionInCredentialsCheck->value(config.getShowEncryptionInCredentials() ? 1 : 0);
        yPos += spacing;
        
        // Default UI Mode
        auto uiModeLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "Default UI Mode:");
        uiModeLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        defaultUIModeChoice = new Fl_Choice(x + labelWidth + 20, yPos, fieldWidth, fieldHeight);
        defaultUIModeChoice->add("CLI");
        defaultUIModeChoice->add("GUI");
        defaultUIModeChoice->value(config.getDefaultUIMode() == "GUI" ? 1 : 0);
        yPos += spacing;
        
        // LFSR Settings Section
        auto lfsrSectionLabel = new Fl_Box(x + 10, yPos, w - 30, fieldHeight, "LFSR Encryption Settings");
        lfsrSectionLabel->labelfont(FL_BOLD);
        lfsrSectionLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        yPos += spacing;
        
        // LFSR Taps
        auto lfsrTapsLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "LFSR Taps (comma separated):");
        lfsrTapsLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        lfsrTapsInput = new Fl_Input(x + labelWidth + 20, yPos, fieldWidth, fieldHeight);
        // Convert vector to string
        std::string tapsStr;
        auto taps = config.getLfsrTaps();
        for (size_t i = 0; i < taps.size(); ++i) {
            if (i > 0) tapsStr += ",";
            tapsStr += std::to_string(taps[i]);
        }
        lfsrTapsInput->value(tapsStr.c_str());
        yPos += spacing;
        
        // LFSR Initial State
        auto lfsrInitStateLabel = new Fl_Box(x + 10, yPos, labelWidth, fieldHeight, "LFSR Init State (comma separated):");
        lfsrInitStateLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        lfsrInitStateInput = new Fl_Input(x + labelWidth + 20, yPos, fieldWidth, fieldHeight);
        // Convert vector to string
        std::string initStateStr;
        auto initState = config.getLfsrInitState();
        for (size_t i = 0; i < initState.size(); ++i) {
            if (i > 0) initStateStr += ",";
            initStateStr += std::to_string(initState[i]);
        }
        lfsrInitStateInput->value(initStateStr.c_str());
        yPos += spacing;
        
        // Add some padding at the bottom of the scroll area
        yPos += 20;
        
        // End scroll area
        scrollArea->end();
        
        // Set scroll area size to accommodate all content
        scrollArea->size(w, h - buttonAreaHeight);
        
        // Buttons outside the scroll area, at the bottom of the dialog
        int buttonY = y + h - buttonAreaHeight + 15;
        Fl_Button* saveButton = createWidget<Fl_Button>(x + w - 180, buttonY, 80, 30, "Save");
        Fl_Button* cancelButton = createWidget<Fl_Button>(x + w - 90, buttonY, 80, 30, "Cancel");
        
        // Set up callbacks
        CallbackHelper::setCallback(saveButton, this, [this](SettingsDialogComponent* comp) {
            comp->saveSettings();
        });
        
        CallbackHelper::setCallback(cancelButton, this, [this](SettingsDialogComponent* comp) {
            if (comp->onCancel) comp->onCancel();
        });
        
        // Force redraw
        if (parent) {
            parent->redraw();
        }
    }
    
    void saveSettings() {
        try {
            ConfigManager& config = ConfigManager::getInstance();
            
            // Parse LFSR settings from input fields
            std::vector<int> newTaps, newInitState;
            
            // Parse LFSR taps
            std::string tapsStr = lfsrTapsInput->value();
            std::stringstream tapsStream(tapsStr);
            std::string tapItem;
            while (std::getline(tapsStream, tapItem, ',')) {
                newTaps.push_back(std::stoi(tapItem));
            }
            
            // Parse LFSR initial state
            std::string initStateStr = lfsrInitStateInput->value();
            std::stringstream initStateStream(initStateStr);
            std::string stateItem;
            while (std::getline(initStateStream, stateItem, ',')) {
                newInitState.push_back(std::stoi(stateItem));
            }
            
            // Check if LFSR settings changed
            bool lfsrChanged = (newTaps != config.getLfsrTaps() || newInitState != config.getLfsrInitState());
            
            if (lfsrChanged) {
                // Prompt for master password to re-encrypt existing credentials
                const char* masterPassword = fl_password("Enter master password to re-encrypt existing LFSR credentials:", "");
                if (!masterPassword || strlen(masterPassword) == 0) {
                    fl_alert("Master password is required to update LFSR settings!");
                    return;
                }
                
                // Update LFSR settings with re-encryption
                if (!config.updateLfsrSettings(newTaps, newInitState, std::string(masterPassword))) {
                    fl_alert("Failed to update LFSR settings. Please check the console for error details.");
                    return;
                }
            } else {
                // Update LFSR settings without re-encryption if they haven't changed
                config.setLfsrTaps(newTaps);
                config.setLfsrInitState(newInitState);
            }
            
            // Update other configuration values
            config.setDataPath(dataPathInput->value());
            config.setDefaultEncryption(static_cast<EncryptionType>(defaultEncryptionChoice->value()));
            config.setMaxLoginAttempts(std::stoi(maxLoginAttemptsInput->value()));
            config.setClipboardTimeoutSeconds(std::stoi(clipboardTimeoutInput->value()));
            config.setAutoClipboardClear(autoClipboardClearCheck->value() == 1);
            config.setRequirePasswordConfirmation(requirePasswordConfirmationCheck->value() == 1);
            config.setMinPasswordLength(std::stoi(minPasswordLengthInput->value()));
            config.setShowEncryptionInCredentials(showEncryptionInCredentialsCheck->value() == 1);
            config.setDefaultUIMode(defaultUIModeChoice->value() == 1 ? "GUI" : "CLI");
            
            // Save to file
            if (config.saveConfig(".config")) {
                if (lfsrChanged) {
                    fl_message("Settings saved successfully!\nExisting LFSR-encrypted credentials have been re-encrypted with new settings.");
                } else {
                    fl_message("Settings saved successfully!");
                }
            } else {
                fl_alert("Failed to save settings to file!");
            }
            
            if (onSave) onSave();
        } catch (const std::exception& e) {
            fl_alert("Error saving settings: %s", e.what());
        }
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
