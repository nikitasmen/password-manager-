#ifndef GUI_H
#define GUI_H

#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Menu_Bar.H>
#include <FL/Fl_Check_Button.H>
#include <FL/fl_message.H>
#include <string>
#include <vector>
#include <memory>
#include "../core/api.h"

class PasswordManagerGUI {
private:
    // Main window
    std::unique_ptr<Fl_Window> mainWindow;
    
    // Login screen components
    std::unique_ptr<Fl_Secret_Input> masterPasswordInput;
    std::unique_ptr<Fl_Button> loginButton;
    
    // Setup screen components
    std::unique_ptr<Fl_Secret_Input> newPasswordInput;
    std::unique_ptr<Fl_Secret_Input> confirmPasswordInput;
    std::unique_ptr<Fl_Button> createPasswordButton;
    
    // Main view components
    std::unique_ptr<Fl_Menu_Bar> menuBar;
    std::unique_ptr<Fl_Text_Display> platformsDisplay;
    std::unique_ptr<Fl_Text_Buffer> platformsBuffer;
    std::vector<std::unique_ptr<Fl_Button>> actionButtons;
    
    // Add credential components
    std::unique_ptr<Fl_Window> addCredentialWindow;
    std::unique_ptr<Fl_Input> platformInput;
    std::unique_ptr<Fl_Input> usernameInput;
    std::unique_ptr<Fl_Secret_Input> passwordInput;
    std::unique_ptr<Fl_Button> saveButton;
    std::unique_ptr<Fl_Button> cancelButton;
    
    // View credential components
    std::unique_ptr<Fl_Window> viewCredentialWindow;
    std::unique_ptr<Fl_Text_Display> credentialDisplay;
    std::unique_ptr<Fl_Text_Buffer> credentialBuffer;
    std::unique_ptr<Fl_Button> closeViewButton;
    
    // Core functionality
    std::unique_ptr<CredentialsManager> credManager;
    bool isLoggedIn;
    std::string masterPassword;
    
    // Window creation helper methods
    void createLoginScreen();
    void createSetupScreen();
    void createMainScreen();
    void createAddCredentialDialog();
    void createViewCredentialDialog(const std::string& platform);
    
    // UI update methods
    void refreshPlatformsList();
    void clearCurrentScreen();
    
    // Memory management helpers
    template <typename T, typename... Args>
    std::unique_ptr<T> makeWidget(Args&&... args) {
        return std::make_unique<T>(std::forward<Args>(args)...);
    }
    
    template <typename T, typename... Args>
    T* addWidget(std::unique_ptr<T>& ptr, Args&&... args) {
        ptr = std::make_unique<T>(std::forward<Args>(args)...);
        return ptr.get();
    }

    // Callback methods
    static void loginCallback(Fl_Widget* w, void* data);
    static void createPasswordCallback(Fl_Widget* w, void* data);
    static void addCredentialCallback(Fl_Widget* w, void* data);
    static void viewCredentialCallback(Fl_Widget* w, void* data);
    static void deleteCredentialCallback(Fl_Widget* w, void* data);
    static void saveCredentialCallback(Fl_Widget* w, void* data);
    static void exitCallback(Fl_Widget* w, void* data);
    static void aboutCallback(Fl_Widget* w, void* data);

public:
    PasswordManagerGUI();
    ~PasswordManagerGUI();
    
    void show();
    void login(const std::string& password);
    void addCredential(const std::string& platform, const std::string& username, const std::string& password);
    void viewCredential(const std::string& platform);
    void deleteCredential(const std::string& platform);
};

#endif // GUI_H
