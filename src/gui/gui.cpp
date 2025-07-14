#include "gui.h"
#include <iostream>
#include <sstream>

PasswordManagerGUI::PasswordManagerGUI() : isLoggedIn(false) {
    credManager = std::make_unique<CredentialsManager>();
    createLoginScreen();
}

PasswordManagerGUI::~PasswordManagerGUI() {
    // Smart pointers automatically clean up
}

void PasswordManagerGUI::show() {
    mainWindow->show();
}

void PasswordManagerGUI::createLoginScreen() {
    // Create main window
    mainWindow = std::make_unique<Fl_Window>(400, 200, "Password Manager - Login");
    mainWindow->begin();
    
    // Add title
    auto titleBox = std::make_unique<Fl_Box>(10, 10, 380, 30, "Password Manager");
    titleBox->labelsize(20);
    
    // Create master password input
    masterPasswordInput = std::make_unique<Fl_Secret_Input>(150, 70, 200, 30, "Master Password:");
    
    // Create login button
    loginButton = std::make_unique<Fl_Button>(150, 120, 100, 30, "Login");
    loginButton->callback(loginCallback, this);
    
    mainWindow->end();
    mainWindow->callback([](Fl_Widget* w, void*) { 
        if (fl_ask("Do you really want to exit?")) {
            w->hide(); 
        }
    });
}

void PasswordManagerGUI::createMainScreen() {
    // Close login window
    mainWindow->hide();
    
    // Create main application window
    mainWindow = std::make_unique<Fl_Window>(600, 400, "Password Manager");
    mainWindow->begin();
    
    // Create menu bar
    menuBar = std::make_unique<Fl_Menu_Bar>(0, 0, 600, 30);
    menuBar->add("File/Add Credential", 0, addCredentialCallback, this);
    menuBar->add("File/Exit", 0, exitCallback, this);
    menuBar->add("Help/About", 0, aboutCallback, this);
    
    // Create text display for showing platforms
    platformsBuffer = std::make_unique<Fl_Text_Buffer>();
    platformsDisplay = std::make_unique<Fl_Text_Display>(20, 50, 560, 300, "Stored Platforms:");
    platformsDisplay->buffer(platformsBuffer.get());
    
    // Refresh the list of platforms
    refreshPlatformsList();
    
    mainWindow->end();
    mainWindow->callback([](Fl_Widget* w, void*) { 
        if (fl_ask("Do you really want to exit?")) {
            w->hide(); 
        }
    });
}

void PasswordManagerGUI::refreshPlatformsList() {
    if (!isLoggedIn) return;
    
    platformsBuffer->text("");
    std::vector<std::string> platforms = credManager->getAllPlatforms();
    
    std::stringstream ss;
    ss << "Double-click a platform to view credentials:\n\n";
    
    for (const auto& platform : platforms) {
        ss << "• " << platform << "\n";
    }
    
    platformsBuffer->text(ss.str().c_str());
    
    // Add double-click event for viewing credentials
    // This would require more complex widget handling in a real implementation
    // For now, we'll just add a simpler approach with buttons
    
    int y = 360;
    auto viewButton = new Fl_Button(20, y, 100, 25, "View");
    viewButton->callback(viewCredentialCallback, this);
    
    auto deleteButton = new Fl_Button(140, y, 100, 25, "Delete");
    deleteButton->callback(deleteCredentialCallback, this);
}

void PasswordManagerGUI::login(const std::string& password) {
    if (credManager->login(password)) {
        isLoggedIn = true;
        masterPassword = password;
        createMainScreen();
    } else {
        fl_alert("Invalid master password!");
    }
}

void PasswordManagerGUI::addCredential(const std::string& platform, 
                                     const std::string& username, 
                                     const std::string& password) {
    if (!isLoggedIn) return;
    
    if (credManager->addCredentials(platform, username, password)) {
        fl_message("Credentials added successfully!");
        refreshPlatformsList();
    } else {
        fl_alert("Failed to add credentials!");
    }
}

void PasswordManagerGUI::viewCredential(const std::string& platform) {
    if (!isLoggedIn) return;
    
    // Get credentials for the platform
    std::vector<std::string> credentials = credManager->getCredentials(platform);
    
    if (credentials.empty()) {
        fl_alert("No credentials found for this platform!");
        return;
    }
    
    // Create a window to display credentials
    viewCredentialWindow = std::make_unique<Fl_Window>(400, 200, ("Credentials for " + platform).c_str());
    viewCredentialWindow->begin();
    
    credentialBuffer = std::make_unique<Fl_Text_Buffer>();
    credentialDisplay = std::make_unique<Fl_Text_Display>(20, 20, 360, 120);
    credentialDisplay->buffer(credentialBuffer.get());
    
    std::stringstream ss;
    ss << "Platform: " << platform << "\n";
    ss << "Username: " << credentials[0] << "\n";
    ss << "Password: " << credentials[1] << "\n";
    
    credentialBuffer->text(ss.str().c_str());
    
    closeViewButton = std::make_unique<Fl_Button>(150, 160, 100, 30, "Close");
    closeViewButton->callback([](Fl_Widget* w, void* data) {
        auto* window = static_cast<Fl_Window*>(w->parent());
        window->hide();
    });
    
    viewCredentialWindow->end();
    viewCredentialWindow->show();
}

void PasswordManagerGUI::deleteCredential(const std::string& platform) {
    if (!isLoggedIn) return;
    
    if (fl_ask("Are you sure you want to delete credentials for %s?", platform.c_str())) {
        if (credManager->deleteCredentials(platform)) {
            fl_message("Credentials deleted successfully!");
            refreshPlatformsList();
        } else {
            fl_alert("Failed to delete credentials!");
        }
    }
}

// Static callback implementations
void PasswordManagerGUI::loginCallback(Fl_Widget* w, void* data) {
    auto* gui = static_cast<PasswordManagerGUI*>(data);
    std::string password = gui->masterPasswordInput->value();
    gui->login(password);
}

void PasswordManagerGUI::addCredentialCallback(Fl_Widget* w, void* data) {
    auto* gui = static_cast<PasswordManagerGUI*>(data);
    
    gui->addCredentialWindow = std::make_unique<Fl_Window>(400, 250, "Add New Credentials");
    gui->addCredentialWindow->begin();
    
    gui->platformInput = std::make_unique<Fl_Input>(150, 30, 200, 30, "Platform:");
    gui->usernameInput = std::make_unique<Fl_Input>(150, 80, 200, 30, "Username:");
    gui->passwordInput = std::make_unique<Fl_Secret_Input>(150, 130, 200, 30, "Password:");
    
    gui->saveButton = std::make_unique<Fl_Button>(100, 200, 80, 30, "Save");
    gui->saveButton->callback(saveCredentialCallback, gui);
    
    gui->cancelButton = std::make_unique<Fl_Button>(220, 200, 80, 30, "Cancel");
    gui->cancelButton->callback([](Fl_Widget* w, void* data) {
        auto* gui = static_cast<PasswordManagerGUI*>(data);
        gui->addCredentialWindow->hide();
    }, gui);
    
    gui->addCredentialWindow->end();
    gui->addCredentialWindow->show();
}

void PasswordManagerGUI::viewCredentialCallback(Fl_Widget* w, void* data) {
    auto* gui = static_cast<PasswordManagerGUI*>(data);
    const char* platform = fl_input("Enter platform name to view:");
    
    if (platform) {
        gui->viewCredential(platform);
    }
}

void PasswordManagerGUI::deleteCredentialCallback(Fl_Widget* w, void* data) {
    auto* gui = static_cast<PasswordManagerGUI*>(data);
    const char* platform = fl_input("Enter platform name to delete:");
    
    if (platform) {
        gui->deleteCredential(platform);
    }
}

void PasswordManagerGUI::saveCredentialCallback(Fl_Widget* w, void* data) {
    auto* gui = static_cast<PasswordManagerGUI*>(data);
    
    std::string platform = gui->platformInput->value();
    std::string username = gui->usernameInput->value();
    std::string password = gui->passwordInput->value();
    
    if (platform.empty() || username.empty() || password.empty()) {
        fl_alert("All fields are required!");
        return;
    }
    
    gui->addCredential(platform, username, password);
    gui->addCredentialWindow->hide();
}

void PasswordManagerGUI::exitCallback(Fl_Widget* w, void* data) {
    if (fl_ask("Do you really want to exit?")) {
        exit(0);
    }
}

void PasswordManagerGUI::aboutCallback(Fl_Widget* w, void* data) {
    fl_message("Password Manager v0.4\n"
               "A secure, lightweight password management tool\n"
               "© 2025 - nikitasmen");
}
