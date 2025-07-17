#include "TerminalUIManager.h"
#include "../core/api.h"
#include <iostream>

TerminalUIManager::TerminalUIManager(const std::string& dataPath)
    : UIManager(dataPath) {
}

void TerminalUIManager::initialize() {
    // Check if this is first time setup or regular login by checking for master password
    bool hasMasterPassword = credManager->hasMasterPassword();
    
    // Perform appropriate initialization based on whether master password exists
    if (!hasMasterPassword) {
        // First time setup
        TerminalUI::display_message("Welcome to Password Manager!");
        TerminalUI::display_message("Please create a master password to get started.");
        
        std::string newPassword = TerminalUI::get_password("Enter new master password: ");
        std::string confirmPassword = TerminalUI::get_password("Confirm master password: ");
        
        setupPassword(newPassword, confirmPassword);
    } else {
        // Regular login
        TerminalUI::display_message("Welcome to Password Manager!");
        TerminalUI::display_message("Please enter your master password to continue.");
        
        // We'll handle the actual login in the show() method
    }
}

int TerminalUIManager::show() {
    try {
        if (!credManager->hasMasterPassword()) {
            // Already handled in initialize()
            return runMenuLoop();
        } else {
            // Login flow
            std::string password;
            int attempts = 0;
            const int MAX_ATTEMPTS = 3;
            
            while (attempts < MAX_ATTEMPTS) {
                password = TerminalUI::get_password("Enter master password: ");
                if (login(password)) {
                    return runMenuLoop();
                }
                
                TerminalUI::display_message("Invalid password! Try again.", true);
                attempts++;
                
                if (attempts == MAX_ATTEMPTS) {
                    TerminalUI::display_message("Too many failed attempts. Exiting...", true);
                    return 1;
                }
            }
        }
    } catch (const std::exception& e) {
        showMessage("Error", e.what(), true);
        return 1;
    }
    
    return 0;
}

bool TerminalUIManager::login(const std::string& password) {
    try {
        if (credManager->login(password)) {
            isLoggedIn = true;
            masterPassword = password;
            return true;
        }
        return false;
    } catch (const std::exception& e) {
        showMessage("Error", e.what(), true);
        return false;
    }
}

bool TerminalUIManager::setupPassword(const std::string& newPassword, const std::string& confirmPassword) {
    try {
        if (newPassword.empty()) {
            showMessage("Error", "Password cannot be empty!", true);
            return false;
        }
        
        if (newPassword != confirmPassword) {
            showMessage("Error", "Passwords do not match!", true);
            return false;
        }
        
        if (credManager->updatePassword(newPassword)) {
            showMessage("Success", "Master password created successfully!");
            isLoggedIn = true;
            masterPassword = newPassword;
            return true;
        }
        
        showMessage("Error", "Failed to create master password!", true);
        return false;
    } catch (const std::exception& e) {
        showMessage("Error", e.what(), true);
        return false;
    }
}

bool TerminalUIManager::addCredential(const std::string& platform, 
                                   const std::string& username, 
                                   const std::string& password) {
    if (!isLoggedIn) return false;
    
    try {
        auto tempCredManager = getFreshCredManager();
        
        if (tempCredManager->addCredentials(platform, username, password)) {
            showMessage("Success", "Credentials added successfully!");
            return true;
        }
        
        showMessage("Error", "Failed to add credentials!", true);
        return false;
    } catch (const std::exception& e) {
        showMessage("Error", e.what(), true);
        return false;
    }
}

void TerminalUIManager::viewCredential(const std::string& platform) {
    if (!isLoggedIn) return;
    
    try {
        auto tempCredManager = getFreshCredManager();
        std::vector<std::string> credentials = tempCredManager->getCredentials(platform);
        
        if (credentials.empty() || credentials.size() < 2) {
            showMessage("Error", "No valid credentials found for this platform!", true);
            return;
        }
        
        // Display the credentials
        TerminalUI::clear_screen();
        TerminalUI::display_message("Credentials for " + platform + ":");
        TerminalUI::display_message("Username: " + credentials[0]);
        TerminalUI::display_message("Password: " + credentials[1]);
    } catch (const std::exception& e) {
        showMessage("Error", e.what(), true);
    }
}

bool TerminalUIManager::deleteCredential(const std::string& platform) {
    if (!isLoggedIn) return false;
    
    try {
        std::string confirmation = TerminalUI::get_input("Are you sure you want to delete credentials for " + 
                                                        platform + "? (y/n): ");
        
        if (confirmation == "y" || confirmation == "Y") {
            auto tempCredManager = getFreshCredManager();
            
            if (tempCredManager->deleteCredentials(platform)) {
                showMessage("Success", "Credentials deleted successfully!");
                return true;
            }
            
            showMessage("Error", "Failed to delete credentials!", true);
        }
        
        return false;
    } catch (const std::exception& e) {
        showMessage("Error", e.what(), true);
        return false;
    }
}

void TerminalUIManager::showMessage(const std::string& title, const std::string& message, bool isError) {
    // In terminal UI, we don't need to show the title separately
    TerminalUI::display_message(message, isError);
    
    if (isError) {
        std::cerr << title << ": " << message << std::endl;
    }
}

int TerminalUIManager::runMenuLoop() {
    if (!isLoggedIn) return 1;
    
    int menu_choice;
    do {
        menu_choice = TerminalUI::display_menu();
        switch (menu_choice) {
        case 1: {
            // Update password
            std::string newPassword = TerminalUI::get_password("Enter new master password: ");
            std::string confirmPassword = TerminalUI::get_password("Confirm new master password: ");
            setupPassword(newPassword, confirmPassword);
            TerminalUI::pause_screen();
            TerminalUI::clear_screen();
            break;
        }
        case 2: {
            // Add credentials
            std::string platform = TerminalUI::get_input("Enter platform name: ");
            std::string username = TerminalUI::get_input("Enter username: ");
            std::string password = TerminalUI::get_password("Enter password: ");
            addCredential(platform, username, password);
            TerminalUI::pause_screen();
            TerminalUI::clear_screen();
            break;
        }
        case 3: {
            // View credentials
            std::string platform = TerminalUI::get_input("Enter platform name to view: ");
            viewCredential(platform);
            TerminalUI::pause_screen();
            TerminalUI::clear_screen();
            break;
        }
        case 4: {
            // Delete credentials
            std::string platform = TerminalUI::get_input("Enter platform name to delete: ");
            deleteCredential(platform);
            TerminalUI::pause_screen();
            TerminalUI::clear_screen();
            break;
        }
        case 5: {
            // List all platforms
            auto tempCredManager = getFreshCredManager();
            std::vector<std::string> platforms = tempCredManager->getAllPlatforms();
            
            TerminalUI::clear_screen();
            TerminalUI::display_message("Available platforms:");
            
            if (platforms.empty()) {
                TerminalUI::display_message("No platforms found.");
            } else {
                for (const auto& platform : platforms) {
                    TerminalUI::display_message("• " + platform);
                }
            }
            
            TerminalUI::pause_screen();
            TerminalUI::clear_screen();
            break;
        }
        }
    } while (menu_choice != 0);
    
    return 0;
}
