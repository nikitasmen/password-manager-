#include "GuiUIManager.h"
#include "../core/api.h"
#include "../core/clipboard.h"
#include "../config/GlobalConfig.h"
#include <FL/fl_ask.H>
#include <FL/Fl_Button.H>
#include <sstream>
#include <filesystem>

GuiUIManager::GuiUIManager(const std::string& dataPath)
    : UIManager(dataPath),
      loginForm(nullptr), passwordSetup(nullptr), platformsDisplay(nullptr), credentialInputs(nullptr) {
}

GuiUIManager::~GuiUIManager() {
    // Clean up all dialog windows first
    cleanupAddCredentialDialog();
    cleanupViewCredentialDialog();
    
    // Then clean up the main window and its components
    cleanupMainWindow();
}

void GuiUIManager::cleanupMainWindow() {
    // Clean up the root component
    if (rootComponent) {
        rootComponent->cleanup();
        rootComponent.reset();
    }
    
    // Reset any component references
    loginForm = nullptr;
    passwordSetup = nullptr;
    platformsDisplay = nullptr;
    credentialInputs = nullptr;
    
    // Finally, destroy the main window
    if (mainWindow) {
        mainWindow->hide();
        mainWindow.reset();
    }
}

void GuiUIManager::initialize() {
    // Check if this is first time setup or regular login by checking for master password
    bool hasMasterPassword = credManager->hasMasterPassword();
    
    // Create appropriate initial screen
    if (!hasMasterPassword) {
        createSetupScreen();
    } else {
        createLoginScreen();
    }
}

int GuiUIManager::show() {
    if (mainWindow) {
        mainWindow->show();
    }
    
    // Return value will be set by the FLTK event loop in the main function
    return 0;
}

bool GuiUIManager::login(const std::string& password) {
    try {
        if (!credManager) {
            std::cerr << "Error: credential manager not initialized!" << std::endl;
            showMessage("Error", "Internal error: credential manager not initialized!", true);
            return false;
        }
        
        std::cout << "Attempting to login with password: [length: " << password.length() << "]" << std::endl;
        
        // Try to login using the credentials manager
        if (credManager->login(password)) {
            std::cout << "Login successful!" << std::endl;
            isLoggedIn = true;
            masterPassword = password;
            createMainScreen();
            return true;
        } else {
            std::cerr << "Login failed: Invalid password" << std::endl;
            showMessage("Error", "Invalid master password!", true);
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in login: " << e.what() << std::endl;
        showMessage("Error", "An error occurred during login", true);
        return false;
    }
}

bool GuiUIManager::setupPassword(const std::string& newPassword, 
                               const std::string& confirmPassword,
                               EncryptionType encryptionType) {
    try {
        if (newPassword.empty()) {
            std::cerr << "Error: Empty password provided" << std::endl;
            showMessage("Error", "Please enter a password!", true);
            return false;
        }
        
        if (newPassword != confirmPassword) {
            std::cerr << "Error: Passwords do not match" << std::endl;
            showMessage("Error", "Passwords do not match!", true);
            return false;
        }
       
        // Set the encryption algorithm
        credManager->setEncryptionType(encryptionType);
        
        // Create the new master password
        if (credManager->updatePassword(newPassword)) {
            std::cout << "Password created successfully!" << std::endl;
            showMessage("Success", "Master password created successfully!");
            isLoggedIn = true;
            masterPassword = newPassword;
            createMainScreen();
            return true;
        } else {
            std::cerr << "Failed to create master password" << std::endl;
            showMessage("Error", "Failed to create master password!", true);
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in setupPassword: " << e.what() << std::endl;
        showMessage("Error", "An error occurred during password setup", true);
        return false;
    }
}

bool GuiUIManager::addCredential(const std::string& platform, const std::string& username, const std::string& password, std::optional<EncryptionType> encryptionType) {
    if (!isLoggedIn) return false;
    if (safeAddCredential(platform, username, password, encryptionType)) {
        showMessage("Success", "Credentials added successfully!");
        refreshPlatformsList();
        return true;
    } else {
        showMessage("Error", "Failed to add credentials!", true);
        return false;
    }
}

void GuiUIManager::viewCredential(const std::string& platform) {
    if (!isLoggedIn) return;
    std::vector<std::string> credentials = safeGetCredentials(platform);
    if (credentials.empty() || credentials.size() < 2) {
        showMessage("Error", "No valid credentials found for this platform!", true);
        return;
    }
    createViewCredentialDialog(platform, credentials);
}

bool GuiUIManager::deleteCredential(const std::string& platform) {
    if (!isLoggedIn) return false;
    std::string message = "Are you sure you want to delete credentials for " + platform + "?";
    if (fl_choice("%s", "Cancel", "Delete", nullptr, message.c_str()) == 1) {
        if (safeDeleteCredential(platform)) {
            showMessage("Success", "Credentials deleted successfully!");
            refreshPlatformsList();
            return true;
        } else {
            showMessage("Error", "Failed to delete credentials!", true);
            return false;
        }
    }
    return false;
}

void GuiUIManager::showMessage(const std::string& title, const std::string& message, bool isError) {
    fl_message_title(title.c_str());
    fl_message("%s", message.c_str());
    if (isError) {
        std::cerr << title << ": " << message << std::endl;
    }
}

void GuiUIManager::createLoginScreen() {
    try {
        // Clean up any existing window and components
        cleanupMainWindow();
        
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

void GuiUIManager::createSetupScreen() {
    try {
        // Clean up any existing window and components
        cleanupMainWindow();
        
        // Create main window for first-time setup
        mainWindow = std::make_unique<Fl_Window>(450, 280, "Password Manager - First Time Setup");
        mainWindow->begin();
        
        // Create root component
        rootComponent = std::make_unique<ContainerComponent>(mainWindow.get(), 0, 0, 450, 280);
        
        // Add title component
        rootComponent->addChild<TitleComponent>(mainWindow.get(), 10, 10, 430, 30, "Password Manager Setup");
        
        // Add description component
        rootComponent->addChild<DescriptionComponent>(
            mainWindow.get(), 20, 50, 410, 30, 
            "Welcome! Please create a master password to get started:"
        );
        
        // Add password setup component
        passwordSetup = rootComponent->addChild<PasswordSetupComponent>(
            mainWindow.get(), 0, 100, 450, 180,
            [this](const std::string& newPassword, const std::string& confirmPassword, EncryptionType encType) {
                setupPassword(newPassword, confirmPassword, encType);
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

void GuiUIManager::createMainScreen() {
    try {
        // Clean up any existing window and components
        cleanupMainWindow();
        
        // Create main application window
        mainWindow = std::make_unique<Fl_Window>(600, 400, "Password Manager");
        mainWindow->begin();
        
        // Create root component
        rootComponent = std::make_unique<ContainerComponent>(mainWindow.get(), 0, 0, 600, 400);
        
        // Add menu bar component
        rootComponent->addChild<MenuBarComponent>(
            mainWindow.get(), 0, 0, 600, 30,
            [this]() { createAddCredentialDialog(); },
            [this]() { openSettingsDialog(); },
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

void GuiUIManager::createAddCredentialDialog() {
    // Clean up existing dialog if it exists
    cleanupAddCredentialDialog();
    
    try {
        // Create the dialog window with more height to accommodate the encryption dropdown
        addCredentialWindow = std::make_unique<Fl_Window>(400, 300, "Add New Credentials");
        addCredentialWindow->begin();
        
        // Create root component for the dialog
        addCredentialRoot = std::make_unique<ContainerComponent>(addCredentialWindow.get(), 0, 0, 400, 300);
        
        // Add credential inputs component with more height for encryption dropdown
        credentialInputs = addCredentialRoot->addChild<CredentialInputsComponent>(
            addCredentialWindow.get(), 0, 30, 400, 220
        );
        
        // Add dialog buttons component positioned lower for the larger dialog
        addCredentialRoot->addChild<CredentialDialogButtonsComponent>(
            addCredentialWindow.get(), 100, 250, 200, 30,
            [this]() {
                // Get inputs
                std::string platform = credentialInputs->getPlatform();
                std::string username = credentialInputs->getUsername();
                std::string password = credentialInputs->getPassword();
                EncryptionType encryptionType = credentialInputs->getEncryptionType();
                
                // Validate inputs
                if (platform.empty() || username.empty() || password.empty()) {
                    showMessage("Error", "All fields are required!", true);
                    return;
                }
                
                // Add credential with the selected encryption type
                addCredential(platform, username, password, encryptionType);
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

void GuiUIManager::createViewCredentialDialog(const std::string& platform, const std::vector<std::string>& credentials) {
    // Clean up existing dialog if it exists
    cleanupViewCredentialDialog();
    
    try {
        // Create the dialog window (increased height for new button)
        viewCredentialWindow = std::make_unique<Fl_Window>(400, 240, ("Credentials for " + platform).c_str());
        viewCredentialWindow->begin();
        
        // Create root component for the dialog
        viewCredentialRoot = std::make_unique<ContainerComponent>(viewCredentialWindow.get(), 0, 0, 400, 240);
        
        // Add credential display component
        auto credDisplay = viewCredentialRoot->addChild<CredentialDisplayComponent>(
            viewCredentialWindow.get(), 20, 20, 360, 120
        );
        
        // Format credential information
        std::stringstream ss;
        ss << "Platform: " << platform << "\n";
        ss << "Username: " << credentials[0] << "\n";
        ss << "Password: " << credentials[1] << "\n";
        
        // Add encryption type if available
        if (credentials.size() >= 3) {
            try {
                int encTypeInt = std::stoi(credentials[2]);
                EncryptionType encType = static_cast<EncryptionType>(encTypeInt);
                std::string encTypeStr = EncryptionUtils::getDisplayName(encType);
                ss << "Encryption: " << encTypeStr << "\n";
            } catch (const std::exception& e) {
                ss << "Encryption: Unknown\n";
            }
        }
        
        // Add clipboard status
        if (ClipboardManager::getInstance().isAvailable()) {
            // Store password for clipboard operation
            std::string password = credentials[1];
            
            // Add Copy Password button component
            auto copyButton = viewCredentialRoot->addChild<ButtonComponent>(
                viewCredentialWindow.get(), 70, 160, 120, 30, "Copy Password",
                [password]() {
                    try {
                        if (ClipboardManager::getInstance().isAvailable()) {
                            ClipboardManager::getInstance().copyToClipboard(password);
                            fl_message("Password copied to clipboard!");
                        } else {
                            fl_alert("Clipboard functionality not available on this system.");
                        }
                    } catch (const ClipboardError& e) {
                        fl_alert("Failed to copy password to clipboard: %s", e.what());
                    }
                }
            );
        } else {
            ss << "\nClipboard functionality not available on this system";
        }
        
       
        
        // Add close button component
        auto closeButton = viewCredentialRoot->addChild<ButtonComponent>(
            viewCredentialWindow.get(), 210, 160, 100, 30, "Close",
            [this]() {
                cleanupViewCredentialDialog();
            }
        );
        
        // Create all components FIRST
        viewCredentialRoot->create();
        
        // THEN set the text in the display
        credDisplay->setText(ss.str());
        
        // Show the dialog
        viewCredentialWindow->end();
        viewCredentialWindow->show();
        
    } catch (const std::exception& e) {
        std::cerr << "Exception in createViewCredentialDialog: " << e.what() << std::endl;
        showMessage("Error", "Failed to create view credential dialog", true);
    }
}

// Generic dialog cleanup helper
namespace {
    template<typename WindowPtr, typename RootPtr>
    void cleanupDialog(WindowPtr& window, RootPtr& root, void*& componentRef) {
        if (root) {
            root->cleanup();
            root.reset();
        }
        if (window) {
            window->hide();
            window.reset();
        }
        if (componentRef) {
            componentRef = nullptr;
        }
    }
    template<typename WindowPtr, typename RootPtr>
    void cleanupDialog(WindowPtr& window, RootPtr& root) {
        if (root) {
            root->cleanup();
            root.reset();
        }
        if (window) {
            window->hide();
            window.reset();
        }
    }
}

void GuiUIManager::cleanupAddCredentialDialog() {
    cleanupDialog(addCredentialWindow, addCredentialRoot, reinterpret_cast<void*&>(credentialInputs));
}

void GuiUIManager::cleanupViewCredentialDialog() {
    cleanupDialog(viewCredentialWindow, viewCredentialRoot);
}

void GuiUIManager::cleanupSettingsDialog() {
    cleanupDialog(settingsWindow, settingsRoot);
}

void GuiUIManager::refreshPlatformsList() {
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

void GuiUIManager::setWindowCloseHandler(Fl_Window* window, bool exitOnClose) {
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

void GuiUIManager::openSettingsDialog() {
    ConfigManager::getInstance().loadConfig(); // Always reload config before showing settings
    createSettingsDialog();
    settingsWindow->show();
}

void GuiUIManager::createSettingsDialog() {
    // Clean up any existing dialog
    cleanupSettingsDialog();
    
    // Create new settings window with larger size to accommodate scrollable content
    settingsWindow = std::make_unique<Fl_Window>(550, 600, "Application Settings");
    settingsWindow->begin();
    
    // Create root container that fills the entire window
    settingsRoot = std::make_unique<ContainerComponent>(settingsWindow.get(), 0, 0, 550, 600);
    
    // Add a simple test to see if the window is working
    auto testLabel = settingsRoot->addChild<TitleComponent>(
        settingsWindow.get(), 10, 10, 530, 30, "Settings", 16
    );
    
    // Add settings form component with more space
    auto settingsForm = settingsRoot->addChild<SettingsDialogComponent>(
        settingsWindow.get(), 10, 50, 530, 500,
        [this]() {
            // On save callback
            cleanupSettingsDialog();
        },
        [this]() {
            // On cancel callback
            cleanupSettingsDialog();
        }
    );
    
    // Create the components BEFORE ending the window
    settingsRoot->create();
    
    settingsWindow->end();
    settingsWindow->set_modal();
    
    // Set close handler
    setWindowCloseHandler(settingsWindow.get(), false);
    
    // Debug: Force redraw
    settingsWindow->redraw();
}
