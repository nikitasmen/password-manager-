#include "gui.h"
#include <iostream>
#include <sstream>
#include "../../GlobalConfig.h"

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

PasswordManagerGUI::PasswordManagerGUI() : isLoggedIn(false) {
    try {
        // Initialize member variables to prevent null pointer issues
        platformsBuffer = nullptr;
        platformsDisplay = nullptr;
        credentialBuffer = nullptr;
        credentialDisplay = nullptr;
        
        // Initialize the credential manager with global data path
        credManager = std::make_unique<CredentialsManager>(data_path);
        
        // Check if the data directory exists, create if not
        if (!fs::exists(data_path)) {
            fs::create_directories(data_path);
            std::cout << "Created data directory: " << data_path << std::endl;
        }
        
        // Check if login file exists - use the global data path
        std::string loginFile = data_path + "/enter";
        bool firstTime = !fs::exists(loginFile);
        
        if (firstTime) {
            createSetupScreen();
        } else {
            createLoginScreen();
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in constructor: " << e.what() << std::endl;
        exit(1);
    }
}

PasswordManagerGUI::~PasswordManagerGUI() {
    // Properly disconnect buffers before destroying
    if (platformsDisplay && platformsBuffer) {
        platformsDisplay->buffer(nullptr);
    }
    
    if (credentialDisplay && credentialBuffer) {
        credentialDisplay->buffer(nullptr);
    }
    
    // Smart pointers will handle the rest of the cleanup
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
        if (fl_choice("Do you really want to exit?", "Cancel", "Exit", nullptr) == 1) {
            w->hide(); 
        }
    });
}

void PasswordManagerGUI::createSetupScreen() {
    // Create main window for first-time setup
    mainWindow = std::make_unique<Fl_Window>(450, 250, "Password Manager - First Time Setup");
    mainWindow->begin();
    
    // Add title
    auto titleBox = std::make_unique<Fl_Box>(10, 10, 430, 30, "Password Manager Setup");
    titleBox->labelsize(20);
    
    // Add description
    auto descBox = std::make_unique<Fl_Box>(20, 50, 410, 30, "Welcome! Please create a master password to get started:");
    
    // Create master password input
    newPasswordInput = std::make_unique<Fl_Secret_Input>(180, 100, 200, 30, "New Master Password:");
    
    // Create confirm password input
    confirmPasswordInput = std::make_unique<Fl_Secret_Input>(180, 150, 200, 30, "Confirm Password:");
    
    // Create setup button
    createPasswordButton = std::make_unique<Fl_Button>(175, 200, 100, 30, "Create");
    createPasswordButton->callback(createPasswordCallback, this);
    
    mainWindow->end();
    mainWindow->callback([](Fl_Widget* w, void*) { 
        if (fl_choice("Do you really want to exit?", "Cancel", "Exit", nullptr) == 1) {
            exit(0); // First time setup is critical, so exit app if canceled
        }
    });
}

void PasswordManagerGUI::createMainScreen() {
    // Before creating a new window, ensure we properly clean up the old one
    if (mainWindow) {
        // Properly clean up any text buffers to avoid callback errors
        if (platformsDisplay && platformsBuffer) {
            platformsDisplay->buffer(nullptr);  // Disconnect buffer before destroying
        }
        
        mainWindow->hide();  // Hide the window
    }
    
    // Reset all pointers to ensure clean state
    menuBar.reset();
    platformsDisplay.reset();
    platformsBuffer.reset();
    
    // Create main application window
    mainWindow = std::make_unique<Fl_Window>(600, 400, "Password Manager");
    if (!mainWindow) {
        std::cerr << "Failed to create main window!" << std::endl;
        return;
    }
    mainWindow->begin();
    
    // Create menu bar
    menuBar = std::make_unique<Fl_Menu_Bar>(0, 0, 600, 30);
    if (menuBar) {
        menuBar->add("File/Add Credential", 0, addCredentialCallback, this);
        menuBar->add("File/Exit", 0, exitCallback, this);
        menuBar->add("Help/About", 0, aboutCallback, this);
    } else {
        std::cerr << "Failed to create menu bar!" << std::endl;
    }
    
    // Create text display for showing platforms
    platformsBuffer = std::make_unique<Fl_Text_Buffer>();
    platformsDisplay = std::make_unique<Fl_Text_Display>(20, 50, 560, 300, "Stored Platforms:");
    if (platformsDisplay && platformsBuffer) {
        platformsDisplay->buffer(platformsBuffer.get());
    }
    
    mainWindow->end();  // End before refreshing to ensure proper widget hierarchy
    
    // Now refresh platforms list
    refreshPlatformsList();
    
    // Set callback for window close
    mainWindow->callback([](Fl_Widget* w, void*) { 
        if (fl_choice("Do you really want to exit?", "Cancel", "Exit", nullptr) == 1) {
            w->hide(); 
        }
    });
}

void PasswordManagerGUI::refreshPlatformsList() {
    if (!isLoggedIn || !mainWindow || !platformsBuffer) {
        return;
    }
    
    // Get platforms data
    std::vector<std::string> platforms;
    try {
        platforms = credManager->getAllPlatforms();
    } catch (const std::exception& e) {
        std::cerr << "Exception in getAllPlatforms: " << e.what() << std::endl;
        return;
    }
    
    // Format and display platforms
    std::stringstream ss;
    ss << "Double-click a platform to view credentials:\n\n";
    
    for (const auto& platform : platforms) {
        ss << "• " << platform << "\n";
    }
    
    platformsBuffer->text(ss.str().c_str());
    
    // Remove all widgets except the menu bar and text display
    // This is a safer approach to avoid memory leaks
    mainWindow->begin();
    
    // Store children that we want to keep
    Fl_Widget* menuBarWidget = menuBar.get();
    Fl_Widget* textDisplayWidget = platformsDisplay.get();
    
    // Remove children we don't want to keep, starting from the end
    // to avoid shifting indices
    for (int i = mainWindow->children() - 1; i >= 0; i--) {
        Fl_Widget* child = mainWindow->child(i);
        if (child != menuBarWidget && child != textDisplayWidget) {
            mainWindow->remove(child);
            delete child; // Safe to delete as we removed it from the parent
        }
    }
    
    // Add new buttons
    int y = 360;
    
    // Use automatic management for these buttons
    Fl_Button* viewButton = new Fl_Button(20, y, 100, 25, "View");
    viewButton->callback(viewCredentialCallback, this);
    
    Fl_Button* deleteButton = new Fl_Button(140, y, 100, 25, "Delete");
    deleteButton->callback(deleteCredentialCallback, this);
    
    mainWindow->end();
}

void PasswordManagerGUI::login(const std::string& password) {
    try {
        if (!credManager) {
            fl_message_title("Error");
            fl_message("Internal error: credential manager not initialized!");
            return;
        }
        
        if (credManager->login(password)) {
            isLoggedIn = true;
            masterPassword = password;
            
            try {
                createMainScreen();
            } catch (const std::exception& e) {
                std::cerr << "Exception in createMainScreen: " << e.what() << std::endl;
                fl_message_title("Error");
                fl_message("Error creating main screen");
            }
        } else {
            fl_message_title("Error");
            fl_message("Invalid master password!");
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in login: " << e.what() << std::endl;
        fl_message_title("Error");
        fl_message("An error occurred during login");
    }
}

void PasswordManagerGUI::addCredential(const std::string& platform, 
                                     const std::string& username, 
                                     const std::string& password) {
    if (!isLoggedIn) return;
    
    if (credManager->addCredentials(platform, username, password)) {
        fl_message_title("Success");
        fl_message("Credentials added successfully!");
        refreshPlatformsList();
    } else {
        fl_message_title("Error");
        fl_message("Failed to add credentials!");
    }
}

void PasswordManagerGUI::viewCredential(const std::string& platform) {
    if (!isLoggedIn) return;
    
    // Get credentials for the platform
    std::vector<std::string> credentials = credManager->getCredentials(platform);
    
    if (credentials.empty() || credentials.size() < 2) {
        fl_message_title("Error");
        fl_message("No valid credentials found for this platform!");
        return;
    }
    
    // Clean up existing window if it exists
    if (viewCredentialWindow) {
        // Disconnect buffer before destroying to avoid callback errors
        if (credentialDisplay && credentialBuffer) {
            credentialDisplay->buffer(nullptr);
        }
        
        viewCredentialWindow->hide();
        viewCredentialWindow.reset();
        credentialDisplay.reset();
        credentialBuffer.reset();
        closeViewButton.reset();
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
        auto* gui = static_cast<PasswordManagerGUI*>(data);
        if (gui && gui->viewCredentialWindow) {
            // Disconnect buffer first
            if (gui->credentialDisplay) {
                gui->credentialDisplay->buffer(nullptr);
            }
            gui->viewCredentialWindow->hide();
        }
    }, this);
    
    viewCredentialWindow->end();
    viewCredentialWindow->show();
}

void PasswordManagerGUI::deleteCredential(const std::string& platform) {
    if (!isLoggedIn) return;
    
    std::string message = "Are you sure you want to delete credentials for " + platform + "?";
    if (fl_choice("%s", "Cancel", "Delete", nullptr, message.c_str()) == 1) {
        if (credManager->deleteCredentials(platform)) {
            fl_message_title("Success");
            fl_message("Credentials deleted successfully!");
            refreshPlatformsList();
        } else {
            fl_message_title("Error");
            fl_message("Failed to delete credentials!");
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
        fl_message_title("Error");
        fl_message("All fields are required!");
        return;
    }
    
    gui->addCredential(platform, username, password);
    gui->addCredentialWindow->hide();
}

void PasswordManagerGUI::exitCallback(Fl_Widget* w, void* data) {
    if (fl_choice("Do you really want to exit?", "Cancel", "Exit", nullptr) == 1) {
        exit(0);
    }
}

void PasswordManagerGUI::aboutCallback(Fl_Widget* w, void* data) {
    fl_message_title("About");
    fl_message("Password Manager v0.4\n"
               "A secure, lightweight password management tool\n"
               "© 2025 - nikitasmen");
}

void PasswordManagerGUI::createPasswordCallback(Fl_Widget* w, void* data) {
    auto* gui = static_cast<PasswordManagerGUI*>(data);
    
    const char* newPass = gui->newPasswordInput->value();
    const char* confirmPass = gui->confirmPasswordInput->value();
    
    if (!newPass || strlen(newPass) == 0) {
        fl_message_title("Error");
        fl_message("Please enter a password!");
        return;
    }
    
    if (strcmp(newPass, confirmPass) != 0) {
        fl_message_title("Error");
        fl_message("Passwords do not match!");
        return;
    }
    
    // Create the new master password
    if (gui->credManager->updatePassword(newPass)) {
        fl_message("Master password created successfully!");
        gui->isLoggedIn = true;
        gui->masterPassword = newPass;
        gui->createMainScreen();
    } else {
        fl_message_title("Error");
        fl_message("Failed to create master password!");
    }
}
