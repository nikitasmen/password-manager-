#include "TerminalUIManager.h"
#include "../core/api.h"
#include "../core/clipboard.h"
#include "../config/GlobalConfig.h"
#include <iostream>
#include <optional>
#include "../utils/EncryptionUtils.h"

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
        TerminalUI::display_message("Please create a master password to get started.\n");
        
        // Show encryption options
        TerminalUI::display_message("Select encryption type:");
        const auto availableTypes = EncryptionUtils::getAllTypes();
        for (size_t i = 0; i < availableTypes.size(); ++i) {
            TerminalUI::display_message(std::to_string(i + 1) + ". " + EncryptionUtils::getDisplayName(availableTypes[i]));
        }

        int choice = 0;
        EncryptionType encryptionType = EncryptionType::AES;

        while (true) {
            std::string input = TerminalUI::get_text_input("Enter your choice: ");
            try {
                choice = std::stoi(input);
                if (choice >= 1 && static_cast<size_t>(choice) <= availableTypes.size()) {
                    encryptionType = availableTypes[choice - 1];
                    break;
                }
                TerminalUI::display_message("Invalid choice. Please enter a valid number.", true);
            } catch (const std::exception&) {
                TerminalUI::display_message("Invalid input. Please enter a number.", true);
            }
        }
        
        std::string newPassword = TerminalUI::get_password_input("\nEnter new master password: ");
        std::string confirmPassword = TerminalUI::get_password_input("Confirm master password: ");

        setupPassword(newPassword, confirmPassword, encryptionType);
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
            
            while (attempts < MAX_LOGIN_ATTEMPTS) {
                password = TerminalUI::get_password_input("Enter master password: ");
                if (login(password)) {
                    return runMenuLoop();
                }
                
                TerminalUI::display_message("Invalid password! Try again.", true);
                attempts++;
                
                if (attempts == MAX_LOGIN_ATTEMPTS) {
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

bool TerminalUIManager::setupPassword(const std::string& newPassword, 
                                const std::string& confirmPassword,
                                EncryptionType encryptionType) {
    try {
        if (newPassword.empty()) {
            showMessage("Error", "Password cannot be empty!", true);
            return false;
        }
        
        if (newPassword != confirmPassword) {
            showMessage("Error", "Passwords do not match!", true);
            return false;
        }
        
        // Set encryption algorithm
        credManager->setEncryptionType(encryptionType);
        
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

bool TerminalUIManager::addCredential(const std::string& platform, const std::string& username, const std::string& password, std::optional<EncryptionType> encryptionType) {
    if (!isLoggedIn) return false;
    if (encryptionType.has_value() && safeAddCredential(platform, username, password, encryptionType.value())) {
        showMessage("Success", "Credentials added successfully!");
        return true;
    } else {
        showMessage("Error", "Failed to add credentials!", true);
        return false;
    }
}

void TerminalUIManager::viewCredential(const std::string& platform) {
    if (!isLoggedIn) return;
    try {
        auto credsOpt = safeGetCredentials(platform);
        if (!credsOpt) {
            showMessage("Info", "No credentials found for " + platform);
            return;
        }

        DecryptedCredential credentials = *credsOpt;

        TerminalUI::clear_screen();
        TerminalUI::display_message("Credentials for " + platform + ":");
        TerminalUI::display_message("Username: " + credentials.username);
        TerminalUI::display_message("Password: " + credentials.password);

        // Ask user if they want to copy password to clipboard
        std::string copyChoice = TerminalUI::get_text_input("\nCopy password to clipboard? (y/n): ");
        if (copyChoice == "y" || copyChoice == "Y") {
            try {
                if (ClipboardManager::getInstance().isAvailable()) {
                    ClipboardManager::getInstance().copyToClipboard(credentials.password);
                    TerminalUI::display_message("Password copied to clipboard for 30 seconds.");
                } else {
                    TerminalUI::display_message("\n️Clipboard functionality not available on this system.");
                }
            } catch (const ClipboardError& e) {
                TerminalUI::display_message("\nFailed to copy password to clipboard: " + std::string(e.what()));
            }
        }
    } catch (const std::exception& e) {
        showMessage("Error", e.what(), true);
    }
}

bool TerminalUIManager::deleteCredential(const std::string& platform) {
    if (!isLoggedIn) return false;
    std::string confirmation = TerminalUI::get_text_input("Are you sure you want to delete credentials for " + platform + "? (y/n): ");
    if (confirmation == "y" || confirmation == "Y") {
        if (safeDeleteCredential(platform)) {
            showMessage("Success", "Credentials deleted successfully!");
            return true;
        } else {
            showMessage("Error", "Failed to delete credentials!", true);
            return false;
        }
    }
    return false;
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
            std::string newPassword = TerminalUI::get_password_input("Enter new master password: ");
            std::string confirmPassword = TerminalUI::get_password_input("Confirm new master password: ");
            setupPassword(newPassword, confirmPassword, EncryptionUtils::getDefault());
            TerminalUI::pause_screen();
            TerminalUI::clear_screen();
            break;
        }
        case 2: {
            // Add credentials
            std::string platform = TerminalUI::get_text_input("Enter platform name: ");
            std::string username = TerminalUI::get_text_input("Enter username: ");
            std::string password = TerminalUI::get_password_input("Enter password: ");
            
            TerminalUI::display_message("\n+---------------------------------------+");
            
            TerminalUI::display_message("|    SELECT ENCRYPTION ALGORITHM       |");
            TerminalUI::display_message("+---------------------------------------+");
            const auto availableTypes = EncryptionUtils::getAllTypes();
            for (size_t i = 0; i < availableTypes.size(); ++i) {
                TerminalUI::display_message(std::to_string(i + 1) + ". " + EncryptionUtils::getDisplayName(availableTypes[i]));
                
                // Add detailed descriptions for each encryption type
                if (availableTypes[i] == EncryptionType::AES) {
                    TerminalUI::display_message("   • Industry-standard symmetric encryption");
                    TerminalUI::display_message("   • Fast and secure for most use cases");
                    TerminalUI::display_message("   • Recommended for general use");
                } else if (availableTypes[i] == EncryptionType::LFSR) {
                    TerminalUI::display_message("   • Linear Feedback Shift Register");
                    TerminalUI::display_message("   • Lightweight stream cipher");
                    TerminalUI::display_message("   • Faster but less secure than AES");
                } else if (availableTypes[i] == EncryptionType::RSA) {
                    TerminalUI::display_message("   • RSA-2048 asymmetric encryption");
                    TerminalUI::display_message("   • ⚠️  WARNING: Key generation takes time!");
                    TerminalUI::display_message("   • Uses public/private key pairs");
                    TerminalUI::display_message("   • Slower than symmetric encryption");
                    TerminalUI::display_message("   • Best for high-security requirements");
                }
                TerminalUI::display_message("");
            }

            int choice = 0;
            EncryptionType selectedEncryption = EncryptionUtils::getDefault();

            while (true) {
                std::string input = TerminalUI::get_text_input("Enter your choice: ");
                try {
                    choice = std::stoi(input);
                    if (choice >= 1 && static_cast<size_t>(choice) <= availableTypes.size()) {
                        selectedEncryption = availableTypes[choice - 1];
                        break;
                    }
                    TerminalUI::display_message("Invalid choice. Please enter a valid number.", true);
                } catch (const std::exception&) {
                    TerminalUI::display_message("Invalid input. Please enter a number.", true);
                }
            }
      
            addCredential(platform, username, password, selectedEncryption);
            TerminalUI::pause_screen();
            TerminalUI::clear_screen();
            break;
        }
        case 3: {
            // View credentials
            std::string platform = TerminalUI::get_text_input("Enter platform name to view: ");
            viewCredential(platform);
            TerminalUI::pause_screen();
            TerminalUI::clear_screen();
            break;
        }
        case 4: {
            // Delete credentials
            std::string platform = TerminalUI::get_text_input("Enter platform name to delete: ");
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
