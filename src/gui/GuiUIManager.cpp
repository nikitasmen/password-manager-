#include "GuiUIManager.h"
#include "GuiComponents.h"
#include "EditCredentialDialog.h"
#include "../core/api.h"
#include "../core/clipboard.h"
#include "../config/GlobalConfig.h"
#include <FL/fl_ask.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Secret_Input.H>  // Add this for password input
#include <FL/Fl_Box.H>           // Add this for labels
#include <sstream>
#include <filesystem>

GuiUIManager::GuiUIManager(const std::string& dataPath)
    : UIManager(dataPath),
      loginForm(nullptr), passwordSetup(nullptr), 
      platformsDisplay(nullptr), clickablePlatformsDisplay(nullptr), 
      credentialInputs(nullptr) {
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
    
    // Clean up the clickable platforms display
    // Note: clickablePlatformsDisplay is a child of mainWindow and will be deleted by FLTK
    clickablePlatformsDisplay = nullptr;
    
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
            UIManager::masterPassword = password;
            std::cout << "Login successful!" << std::endl;
            isLoggedIn = true;
            createMainScreen();
            refreshPlatformsList();
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

            // Automatically log the user in
            return login(newPassword);
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
    if (!isLoggedIn) {
        showMessage("Error", "You must be logged in to view credentials", true);
        return;
    }
    
    try {
        auto credsOpt = safeGetCredentials(platform);
        createViewCredentialDialog(platform, credsOpt);
    } catch (const std::exception& e) {
        std::cerr << "Error in viewCredential: " << e.what() << std::endl;
        showMessage("Error", "Failed to retrieve credentials: " + std::string(e.what()), true);
    }
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

void GuiUIManager::createScreen(const std::string& title, int w, int h, std::function<void()> populateScreen) {
    try {
        // Clean up any existing main window and components before creating a new screen
        cleanupMainWindow();

        // 1. Create the main window for the new screen
        mainWindow = std::make_unique<Fl_Window>(w, h, title.c_str());
        setWindowCloseHandler(mainWindow.get(), true); // Exit app on close
        mainWindow->begin();

        // 2. Create the root container for the screen's components
        rootComponent = std::make_unique<ContainerComponent>(mainWindow.get(), 0, 0, w, h);

        // 3. Let the caller populate the screen with specific components
        populateScreen();

        // 4. Create all components that were added to the root
        rootComponent->create();

        // 5. End window definition and show it
        mainWindow->end();
        mainWindow->show();

    } catch (const std::exception& e) {
        std::cerr << "Exception in createScreen: " << e.what() << std::endl;
        showMessage("Error", "Failed to create screen: " + std::string(e.what()), true);
    }
}

void GuiUIManager::createLoginScreen() {
    createScreen("Login", 400, 200, [this]() {
        loginForm = rootComponent->addChild<LoginFormComponent>(
            mainWindow.get(), 20, 20, 360, 160, 
            [this](const std::string& pass) { this->login(pass); }
        );
    });
}

void GuiUIManager::createSetupScreen() {
    createScreen("First Time Setup", 500, 300, [this]() {
        passwordSetup = rootComponent->addChild<PasswordSetupComponent>(
            mainWindow.get(), 20, 20, 460, 260,
            [this](const std::string& newPass, const std::string& confirmPass, EncryptionType encType) {
                this->setupPassword(newPass, confirmPass, encType);
            }
        );
    });
}

void GuiUIManager::createMainScreen() {
    try {
        createScreen("Password Manager", 600, 450, [this]() {
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
                    fl_message("Password Manager v1.5\n"
                               "A secure, lightweight password management tool\n"
                               "2025 - nikitasmen");
                }
            );

            // Create the clickable platforms display directly in the main window
            clickablePlatformsDisplay = new ClickablePlatformsDisplay(
                20, 50, 560, 300
            );
            mainWindow->add(clickablePlatformsDisplay);
            
            // Set up click callback
            clickablePlatformsDisplay->setClickCallback(
                [this](ClickablePlatformsDisplay*, const std::string& platform) {
                    this->viewCredential(platform);
                }
            );

            rootComponent->addChild<ActionButtonsComponent>(
                mainWindow.get(), 20, 360, 240, 25,
                [this]() {
                    const char* platform = fl_input("Enter platform name to view:");
                    if (platform && strlen(platform) > 0) {
                        viewCredential(platform);
                    }
                },
                [this]() {
                    const char* platform = fl_input("Enter platform name to delete:");
                    if (platform && strlen(platform) > 0) {
                        if (fl_choice("Are you sure you want to delete this credential?", "Cancel", "Yes", nullptr) == 1) {
                            deleteCredential(platform);
                        }
                    }
                }
            );

        });
    } catch (const std::exception& e) {
        std::cerr << "Error creating main screen: " << e.what() << std::endl;
        showMessage("Error", "Failed to create main screen: " + std::string(e.what()), true);
    }
}

void GuiUIManager::createAddCredentialDialog() {
    // Clean up existing dialog if it exists
    cleanupAddCredentialDialog();
    
    try {
        // Create the dialog window with more height to accommodate the encryption dropdown
        addCredentialWindow = std::make_unique<Fl_Window>(450, 400, "Add New Credentials");
        addCredentialWindow->begin();
        
        // Create root component for the dialog
        addCredentialRoot = std::make_unique<ContainerComponent>(addCredentialWindow.get(), 0, 0, 450, 400);
        
        // Add credential inputs component with more height and space for encryption dropdown
        credentialInputs = addCredentialRoot->addChild<CredentialInputsComponent>(
            addCredentialWindow.get(), 25, 20, 400, 300
        );
        
        // Add dialog buttons component positioned at the bottom of the dialog
        addCredentialRoot->addChild<CredentialDialogButtonsComponent>(
            addCredentialWindow.get(), 125, 340, 200, 30,
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

void GuiUIManager::createViewCredentialDialog(const std::string& platform, const std::optional<DecryptedCredential>& credentials) {
    // Clean up existing dialog if it exists
    cleanupViewCredentialDialog();

    try {
        // Create the dialog window
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
        
        if (credentials) {
            ss << "Username: " << credentials->username << "\n";
            ss << "Password: " << credentials->password << "\n";

            // Add buttons
        int buttonY = 160;
        int buttonWidth = 120;
        int buttonSpacing = 10;
        
        // Add Copy Password button if clipboard is available
            if (ClipboardManager::getInstance().isAvailable()) {
                // Store password for clipboard operation
                std::string password = credentials->password;

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
        
        // Add Edit button that will open the EditCredentialDialog
        auto editButton = viewCredentialRoot->addChild<ButtonComponent>(
            viewCredentialWindow.get(), 150, buttonY, buttonWidth, 30, "Edit Credentials",
            [this, platform = platform, username = credentials.username]() {
                try {
                    // Use the existing logged-in credential manager
                    if (!credManager) {
                        throw std::runtime_error("Not logged in");
                    }
                    
                    // Create and show the edit dialog with the existing manager
                    auto dialog = std::make_unique<EditCredentialDialog>(
                        platform,
                        username,
                        credManager.get(),  // Use the logged-in manager
                        [this, platform](bool success) {
                            if (success) {
                                // Refresh the view with updated credentials
                                cleanupViewCredentialDialog();
                                auto updatedCreds = safeGetCredentials(platform);
                                if (updatedCreds) {
                                    createViewCredentialDialog(platform, *updatedCreds);
                                }
                            }
                        }
                    );
                    
                    // Show the dialog
                    dialog->show();
                    
                    // The dialog will manage its own lifetime
                    dialog.release();
                    
                } catch (const std::exception& e) {
                    std::cerr << "Error in edit credentials handler: " << e.what() << std::endl;
                    showMessage("Error", std::string("Failed to edit credentials: ") + e.what(), true);
                }
            }
        );

        // Add close button component
        int closeButtonY = credentials ? 160 : 100; // Adjust Y position based on content
        auto closeButton = viewCredentialRoot->addChild<ButtonComponent>(
            viewCredentialWindow.get(), 150, closeButtonY, 100, 30, "Close",
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
        showMessage("Error", "Failed to create view credential dialog: " + std::string(e.what()), true);
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

bool GuiUIManager::updateCredential(const std::string& platform, 
                                  const std::string& username,
                                  const std::string& password) {
    try {
        // Input validation
        if (platform.empty() || username.empty() || password.empty()) {
            showMessage("Error", "Platform, username, and password cannot be empty", true);
            return false;
        }

        // Get a fresh credential manager instance
        auto tempCredManager = getFreshCredManager();
        if (!tempCredManager) {
            showMessage("Error", "Failed to initialize credential manager", true);
            return false;
        }

        // Get the current credential to check if it exists
        auto existingCreds = tempCredManager->getCredentials(platform);
        if (!existingCreds) {
            showMessage("Error", "No credentials found for platform: " + platform, true);
            return false;
        }

        // Check if anything actually changed
        if (existingCreds->username == username && existingCreds->password == password) {
            showMessage("Info", "No changes detected");
            return true;
        }

        // Use the new CredentialsManager::updateCredentials method
        if (!tempCredManager->updateCredentials(platform, username, password)) {
            showMessage("Error", "Failed to update credentials", true);
            return false;
        }

        // Refresh the UI if we're currently viewing the updated credential
        if (viewCredentialWindow && viewCredentialWindow->shown()) {
            cleanupViewCredentialDialog();
            auto updatedCreds = tempCredManager->getCredentials(platform);
            if (updatedCreds) {
                createViewCredentialDialog(platform, *updatedCreds);
            }
        }

        // Refresh the platforms list in case the update affects sorting
        refreshPlatformsList();

        showMessage("Success", "Credentials updated successfully");
        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error updating credential: " << e.what() << std::endl;
        showMessage("Error", std::string("Failed to update credentials: ") + e.what(), true);
        return false;
    }
}

void GuiUIManager::cleanupSettingsDialog() {
    cleanupDialog(settingsWindow, settingsRoot);
}

void GuiUIManager::refreshPlatformsList() {
    if (!isLoggedIn || !mainWindow || !clickablePlatformsDisplay) {
        return;
    }
    
    try {
        // Get fresh credentials manager and retrieve platforms
        auto tempCredManager = getFreshCredManager();
        std::vector<std::string> platforms = tempCredManager->getAllPlatforms();
        
        // Update the clickable platforms display
        clickablePlatformsDisplay->setPlatforms(platforms);
        
        // The click callback is already set up in createMainScreen
        
        // Force a redraw to update the display
        if (clickablePlatformsDisplay->window()) {
            clickablePlatformsDisplay->window()->redraw();
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in refreshPlatformsList: " << e.what() << std::endl;
        showMessage("Error", std::string("Failed to refresh platforms: ") + e.what(), true);
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
    // Explicitly load from the .config file in the project root
    ConfigManager::getInstance().loadConfig(".config");
    createSettingsDialog();
    settingsWindow->show();
}

void GuiUIManager::createSettingsDialog() {
    if (settingsWindow) {
        settingsWindow->show();
        return;
    }

    settingsWindow = std::make_unique<Fl_Window>(550, 600, "Settings");
    settingsRoot = std::make_unique<ContainerComponent>(settingsWindow.get(), 0, 0, 550, 600);

    const auto& config = ConfigManager::getInstance().getConfig();
    auto settingsDialog = settingsRoot->addChild<SettingsDialogComponent>(
        settingsWindow.get(), 0, 0, 550, 600, masterPassword, config,
        [this]() { cleanupSettingsDialog(); },
        [this]() { cleanupSettingsDialog(); }
    );

    settingsRoot->create();
    settingsWindow->end();
    settingsWindow->set_modal();
}
