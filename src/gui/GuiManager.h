#ifndef GUI_MANAGER_H
#define GUI_MANAGER_H

#include "GuiComponents.h"
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/fl_message.H>
#include <vector>
#include <memory>
#include <string>
#include <functional>
#include <iostream>

// Forward declaration
class CredentialsManager;

class GuiManager {
private:
    // Main window
    std::unique_ptr<Fl_Window> mainWindow;
    
    // Root component
    std::unique_ptr<ContainerComponent> rootComponent;
    
    // Dialog windows and their root components
    std::unique_ptr<Fl_Window> addCredentialWindow;
    std::unique_ptr<ContainerComponent> addCredentialRoot;
    std::unique_ptr<Fl_Window> viewCredentialWindow;
    std::unique_ptr<ContainerComponent> viewCredentialRoot;
    
    // Component references
    LoginFormComponent* loginForm;
    PasswordSetupComponent* passwordSetup;
    PlatformsDisplayComponent* platformsDisplay;
    CredentialInputsComponent* credentialInputs;
    
    // Credentials manager
    std::unique_ptr<CredentialsManager> credManager;
    bool isLoggedIn;
    std::string masterPassword;
    std::string dataPath;

public:
    GuiManager(const std::string& dataPath);
    ~GuiManager();
    
    // Core methods
    void show();
    void initialize();
    
    // Screen creation methods
    void createLoginScreen();
    void createSetupScreen();
    void createMainScreen();
    void createAddCredentialDialog();
    void createViewCredentialDialog(const std::string& platform, const std::vector<std::string>& credentials);
    
    // Action methods
    void login(const std::string& password);
    void setupPassword(const std::string& newPassword, const std::string& confirmPassword);
    void addCredential(const std::string& platform, const std::string& username, const std::string& password);
    void viewCredential(const std::string& platform);
    void deleteCredential(const std::string& platform);
    void refreshPlatformsList();
    
    // Dialog methods
    void cleanupAddCredentialDialog();
    void cleanupViewCredentialDialog();
    
    // Helper methods
    void showMessage(const std::string& title, const std::string& message, bool isError = false);
    void setWindowCloseHandler(Fl_Window* window, bool exitOnClose = false);
    std::unique_ptr<CredentialsManager> getFreshCredManager();
};

#endif // GUI_MANAGER_H
