#include "GuiManager.h"
#include "../core/api.h"
#include "../config/GlobalConfig.h"
#include <sstream>

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

GuiManager::GuiManager(const std::string& dataPath)
    : isLoggedIn(false), dataPath(dataPath),
      loginForm(nullptr), passwordSetup(nullptr), platformsDisplay(nullptr), credentialInputs(nullptr) {
    
    try {
        // Initialize the credential manager with data path
        credManager = std::make_unique<CredentialsManager>(dataPath);
        
        // Ensure data directory exists
        fs::path dir(dataPath);
        if (!fs::exists(dir)) {
            fs::create_directories(dir);
        }
        
        initialize();
    } catch (const std::exception& e) {
        std::cerr << "Error in GuiManager constructor: " << e.what() << std::endl;
        exit(1);
    }
}

GuiManager::~GuiManager() {
    // Clean up all dialog windows first
    cleanupAddCredentialDialog();
    cleanupViewCredentialDialog();
    
    // Then clean up the main component
    if (rootComponent) {
        rootComponent->cleanup();
        rootComponent.reset();
    }
    
    // Reset any component references
    loginForm = nullptr;
    passwordSetup = nullptr;
    platformsDisplay = nullptr;
    credentialInputs = nullptr;
    
    // Clean up credential manager
    credManager.reset();
    
    // Finally, destroy the main window
    if (mainWindow) {
        mainWindow->hide();
        mainWindow.reset();
    }
}

void GuiManager::initialize() {
    // Check if this is first time setup or regular login by checking for master password
    bool hasMasterPassword = credManager->hasMasterPassword();
    
    // Create appropriate initial screen
    if (!hasMasterPassword) {
        createSetupScreen();
    } else {
        createLoginScreen();
    }
}

void GuiManager::show() {
    if (mainWindow) {
        mainWindow->show();
    }
}

void GuiManager::createLoginScreen() {
    try {
        // Create main window
        mainWindow = std::make_unique<Fl_Window>(400, 200, "Password Manager - Login");
        mainWindow->begin();
        
        // Create root component (using ContainerComponent as a concrete implementation)
        rootComponent = std::make_unique<ContainerComponent>(mainWindow.get(), 0, 0, 400, 200);
        
        // Add title component
        rootComponent->addChild<TitleComponent>(mainWindow.get(), 10, 10, 380, 30, "Password Manager");
        
        // Add login form component
        loginForm = rootComponent->addChild<LoginFormComponent>(
            mainWindow.get(), 20, 60, 360, 100,
            [this](const std::string& password) {
                login(password);
            }
        );
        
        // Create all components
        rootComponent->create();
        
        // Set up window close handler
        mainWindow->end();
        setWindowCloseHandler(mainWindow.get());
        
        // Show the window after it's fully configured
        mainWindow->show();
        
    } catch (const std::exception& e) {
        std::cerr << "Error creating login screen: " << e.what() << std::endl;
        showMessage("Error", "Failed to create login screen: " + std::string(e.what()), true);
    }
}

void GuiManager::createSetupScreen() {
    try {
        // Create main window for first-time setup
        mainWindow = std::make_unique<Fl_Window>(450, 250, "Password Manager - First Time Setup");
        mainWindow->begin();
        
        // Create root component
        rootComponent = std::make_unique<ContainerComponent>(mainWindow.get(), 0, 0, 450, 250);
        
        // Add title component
        rootComponent->addChild<TitleComponent>(mainWindow.get(), 10, 10, 430, 30, "Password Manager Setup");
        
        // Add description component
        rootComponent->addChild<DescriptionComponent>(
            mainWindow.get(), 20, 50, 410, 30, 
            "Welcome! Please create a master password to get started:"
        );
        
        // Add password setup component
        passwordSetup = rootComponent->addChild<PasswordSetupComponent>(
            mainWindow.get(), 0, 100, 450, 150,
            [this](const std::string& newPassword, const std::string& confirmPassword) {
                setupPassword(newPassword, confirmPassword);
            }
        );
        
        // Create all components
        rootComponent->create();
        
        // Set up window close handler - first time setup is critical
        mainWindow->end();
        setWindowCloseHandler(mainWindow.get(), true);
        
        // Show the window after it's fully configured
        mainWindow->show();
        
    } catch (const std::exception& e) {
        std::cerr << "Error creating setup screen: " << e.what() << std::endl;
        showMessage("Error", "Failed to create setup screen: " + std::string(e.what()), true);
    }
}

void GuiManager::createMainScreen() {
    try {
        // If there's an existing window, properly clean it up
        if (mainWindow) {
            if (rootComponent) {
                rootComponent->cleanup();
                rootComponent.reset();
            }
            mainWindow->hide();
        }
        
        // Create main application window
        mainWindow = std::make_unique<Fl_Window>(600, 400, "Password Manager");
        mainWindow->begin();
        
        // Create root component
        rootComponent = std::make_unique<ContainerComponent>(mainWindow.get(), 0, 0, 600, 400);
        
        // Add menu bar component
        rootComponent->addChild<MenuBarComponent>(
            mainWindow.get(), 0, 0, 600, 30,
            [this]() { createAddCredentialDialog(); },
            []() { 
                if (fl_choice("Do you really want to exit?", "Cancel", "Exit", nullptr) == 1) {
                    exit(0);
                }
            },
            []() {
                fl_message_title("About");
                fl_message("Password Manager v0.4\n"
                           "A secure, lightweight password management tool\n"
                           "© 2025 - nikitasmen");
            }
        );
        
        // Add platforms display component
        platformsDisplay = rootComponent->addChild<PlatformsDisplayComponent>(
            mainWindow.get(), 20, 50, 560, 300
        );
        
        // Add action buttons component
        rootComponent->addChild<ActionButtonsComponent>(
            mainWindow.get(), 20, 360, 240, 25,
            [this]() {
                const char* platform = fl_input("Enter platform name to view:");
                if (platform) {
                    viewCredential(platform);
                }
            },
            [this]() {
                const char* platform = fl_input("Enter platform name to delete:");
                if (platform) {
                    deleteCredential(platform);
                }
            }
        );
        
        // Create all components
        rootComponent->create();
        
        // Populate the platforms list
        refreshPlatformsList();
        
        // Set up window close handler
        mainWindow->end();
        setWindowCloseHandler(mainWindow.get());
        
        // Show the window after it's fully configured
        mainWindow->show();
        
    } catch (const std::exception& e) {
        std::cerr << "Exception in createMainScreen: " << e.what() << std::endl;
        showMessage("Error", "Failed to create main screen", true);
    }
}

void GuiManager::createAddCredentialDialog() {
    // Clean up existing dialog if it exists
    cleanupAddCredentialDialog();
    
    try {
        // Create the dialog window
        addCredentialWindow = std::make_unique<Fl_Window>(400, 250, "Add New Credentials");
        addCredentialWindow->begin();
        
        // Create root component for the dialog
        addCredentialRoot = std::make_unique<ContainerComponent>(addCredentialWindow.get(), 0, 0, 400, 250);
        
        // Add credential inputs component
        credentialInputs = addCredentialRoot->addChild<CredentialInputsComponent>(
            addCredentialWindow.get(), 0, 30, 400, 170
        );
        
        // Add dialog buttons component
        addCredentialRoot->addChild<CredentialDialogButtonsComponent>(
            addCredentialWindow.get(), 100, 200, 200, 30,
            [this]() {
                // Get inputs
                std::string platform = credentialInputs->getPlatform();
                std::string username = credentialInputs->getUsername();
                std::string password = credentialInputs->getPassword();
                
                // Validate inputs
                if (platform.empty() || username.empty() || password.empty()) {
                    showMessage("Error", "All fields are required!", true);
                    return;
                }
                
                // Add credential
                addCredential(platform, username, password);
                cleanupAddCredentialDialog();
            },
            [this]() {
                cleanupAddCredentialDialog();
            }
        );
        
        // Create all components
        addCredentialRoot->create();
        
        // Show the dialog
        addCredentialWindow->end();
        addCredentialWindow->show();
        
    } catch (const std::exception& e) {
        std::cerr << "Exception in createAddCredentialDialog: " << e.what() << std::endl;
        showMessage("Error", "Failed to create add credential dialog", true);
    }
}

void GuiManager::createViewCredentialDialog(const std::string& platform, const std::vector<std::string>& credentials) {
    // Clean up existing dialog if it exists
    cleanupViewCredentialDialog();
    
    try {
        // Create the dialog window
        viewCredentialWindow = std::make_unique<Fl_Window>(400, 200, ("Credentials for " + platform).c_str());
        viewCredentialWindow->begin();
        
        // Create root component for the dialog
        viewCredentialRoot = std::make_unique<ContainerComponent>(viewCredentialWindow.get(), 0, 0, 400, 200);
        
        // Add credential display component
        auto credDisplay = viewCredentialRoot->addChild<CredentialDisplayComponent>(
            viewCredentialWindow.get(), 20, 20, 360, 120
        );
        
        // Format credential information
        std::stringstream ss;
        ss << "Platform: " << platform << "\n";
        ss << "Username: " << credentials[0] << "\n";
        ss << "Password: " << credentials[1] << "\n";
        
        // Add close button component
        viewCredentialRoot->addChild<CloseButtonComponent>(
            viewCredentialWindow.get(), 150, 160, 100, 30,
            [this]() {
                cleanupViewCredentialDialog();
            }
        );
        
        // Create all components
        viewCredentialRoot->create();
        
        // Set the text in the display
        credDisplay->setText(ss.str());
        
        // Show the dialog
        viewCredentialWindow->end();
        viewCredentialWindow->show();
        
    } catch (const std::exception& e) {
        std::cerr << "Exception in createViewCredentialDialog: " << e.what() << std::endl;
        showMessage("Error", "Failed to create view credential dialog", true);
    }
}

void GuiManager::login(const std::string& password) {
    try {
        if (!credManager) {
            std::cerr << "Error: credential manager not initialized!" << std::endl;
            showMessage("Error", "Internal error: credential manager not initialized!", true);
            return;
        }
        
        std::cout << "Attempting to login with password: [length: " << password.length() << "]" << std::endl;
        
        // Try to login using the credentials manager
        if (credManager->login(password)) {
            std::cout << "Login successful!" << std::endl;
            isLoggedIn = true;
            masterPassword = password;
            createMainScreen();
        } else {
            std::cerr << "Login failed: Invalid password" << std::endl;
            showMessage("Error", "Invalid master password!", true);
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in login: " << e.what() << std::endl;
        showMessage("Error", "An error occurred during login", true);
    }
}

void GuiManager::setupPassword(const std::string& newPassword, const std::string& confirmPassword) {
    try {
        if (newPassword.empty()) {
            std::cerr << "Error: Empty password provided" << std::endl;
            showMessage("Error", "Please enter a password!", true);
            return;
        }
        
        if (newPassword != confirmPassword) {
            std::cerr << "Error: Passwords do not match" << std::endl;
            showMessage("Error", "Passwords do not match!", true);
            return;
        }
        
        std::cout << "Attempting to create master password with length: " << newPassword.length() << std::endl;
        
        // Create the new master password
        if (credManager->updatePassword(newPassword)) {
            std::cout << "Password created successfully!" << std::endl;
            showMessage("Success", "Master password created successfully!");
            isLoggedIn = true;
            masterPassword = newPassword;
            createMainScreen();
        } else {
            std::cerr << "Failed to create master password" << std::endl;
            showMessage("Error", "Failed to create master password!", true);
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in setupPassword: " << e.what() << std::endl;
        showMessage("Error", "An error occurred during password setup", true);
    }
}

void GuiManager::addCredential(const std::string& platform, 
                              const std::string& username, 
                              const std::string& password) {
    if (!isLoggedIn) return;
    
    try {
        // Get fresh credentials manager
        auto tempCredManager = getFreshCredManager();
        
        if (tempCredManager->addCredentials(platform, username, password)) {
            showMessage("Success", "Credentials added successfully!");
            refreshPlatformsList();
        } else {
            showMessage("Error", "Failed to add credentials!", true);
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in addCredential: " << e.what() << std::endl;
        showMessage("Error", "An error occurred while adding credentials", true);
    }
}

void GuiManager::viewCredential(const std::string& platform) {
    if (!isLoggedIn) return;
    
    try {
        // Get fresh credentials manager
        auto tempCredManager = getFreshCredManager();
        
        // Get credentials for the platform
        std::vector<std::string> credentials = tempCredManager->getCredentials(platform);
        
        if (credentials.empty() || credentials.size() < 2) {
            showMessage("Error", "No valid credentials found for this platform!", true);
            return;
        }
        
        // Create and show the view credential dialog
        createViewCredentialDialog(platform, credentials);
    } catch (const std::exception& e) {
        std::cerr << "Exception in viewCredential: " << e.what() << std::endl;
        showMessage("Error", "An error occurred while retrieving credentials", true);
    }
}

void GuiManager::deleteCredential(const std::string& platform) {
    if (!isLoggedIn) return;
    
    try {
        std::string message = "Are you sure you want to delete credentials for " + platform + "?";
        if (fl_choice("%s", "Cancel", "Delete", nullptr, message.c_str()) == 1) {
            // Get fresh credentials manager
            auto tempCredManager = getFreshCredManager();
            
            if (tempCredManager->deleteCredentials(platform)) {
                showMessage("Success", "Credentials deleted successfully!");
                refreshPlatformsList();
            } else {
                showMessage("Error", "Failed to delete credentials!", true);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in deleteCredential: " << e.what() << std::endl;
        showMessage("Error", "An error occurred while deleting credentials", true);
    }
}

void GuiManager::refreshPlatformsList() {
    if (!isLoggedIn || !mainWindow || !platformsDisplay) {
        return;
    }
    
    try {
        // Get fresh credentials manager and retrieve platforms
        auto tempCredManager = getFreshCredManager();
        std::vector<std::string> platforms = tempCredManager->getAllPlatforms();
        
        // Format platform information
        std::stringstream ss;
        ss << "Double-click a platform to view credentials:\n\n";
        
        for (const auto& platform : platforms) {
            ss << "• " << platform << "\n";
        }
        
        // Set the text in the display
        platformsDisplay->setText(ss.str());
    } catch (const std::exception& e) {
        std::cerr << "Exception in refreshPlatformsList: " << e.what() << std::endl;
    }
}

void GuiManager::cleanupAddCredentialDialog() {
    if (addCredentialRoot) {
        // First cleanup all the components
        addCredentialRoot->cleanup();
        addCredentialRoot.reset();
    }
    
    if (addCredentialWindow) {
        // Then hide and destroy the window
        addCredentialWindow->hide();
        addCredentialWindow.reset();
    }
    
    // Reset component reference
    credentialInputs = nullptr;
}

void GuiManager::cleanupViewCredentialDialog() {
    if (viewCredentialRoot) {
        // First cleanup all the components
        viewCredentialRoot->cleanup();
        viewCredentialRoot.reset();
    }
    
    if (viewCredentialWindow) {
        // Then hide and destroy the window
        viewCredentialWindow->hide();
        viewCredentialWindow.reset();
    }
}

void GuiManager::showMessage(const std::string& title, const std::string& message, bool isError) {
    fl_message_title(title.c_str());
    fl_message("%s", message.c_str());
    if (isError) {
        std::cerr << title << ": " << message << std::endl;
    }
}

void GuiManager::setWindowCloseHandler(Fl_Window* window, bool exitOnClose) {
    if (!window) return;
    
    window->callback([](Fl_Widget* w, void* data) { 
        bool exitApp = static_cast<bool>(reinterpret_cast<uintptr_t>(data));
        if (fl_choice("Do you really want to exit?", "Cancel", "Exit", nullptr) == 1) {
            if (exitApp) {
                exit(0); 
            } else {
                w->hide();
            }
        }
    }, reinterpret_cast<void*>(static_cast<uintptr_t>(exitOnClose)));
}

std::unique_ptr<CredentialsManager> GuiManager::getFreshCredManager() {
    auto manager = std::make_unique<CredentialsManager>(dataPath);
    if (isLoggedIn) {
        manager->login(masterPassword);
    }
    return manager;
}
