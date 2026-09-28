#include "TerminalUIManager.h"

#include <iostream>
#include <optional>

#include "../config/GlobalConfig.h"
#include "../core/clipboard.h"
#include "../utils/EncryptionUtils.h"

namespace {

// Numbered cipher menu; returns the default on empty input.
CipherAlg chooseCipher(const std::string& title) {
    const auto& types = allCiphers();
    const CipherAlg def = encryption_utils::getDefault();
    TerminalUI::display_message(title);
    for (size_t i = 0; i < types.size(); ++i) {
        std::string line = std::to_string(i + 1) + ". " + encryption_utils::getDisplayName(types[i]);
        if (types[i] == def) line += "  (default)";
        TerminalUI::display_message(line);
    }
    while (true) {
        std::string input = TerminalUI::get_text_input("Enter your choice (Enter = default): ");
        if (input.empty()) return def;
        try {
            int choice = std::stoi(input);
            if (choice >= 1 && static_cast<size_t>(choice) <= types.size()) return types[choice - 1];
        } catch (const std::exception&) {
        }
        TerminalUI::display_message("Invalid choice. Please enter a valid number.", true);
    }
}

}  // namespace

TerminalUIManager::TerminalUIManager(const std::string& dataPath) : UIManager(dataPath) {
}

void TerminalUIManager::initialize() {
    TerminalUI::display_message("Welcome to Password Manager!");
    if (!vault->exists()) {
        TerminalUI::display_message("No vault found. Create a master password to get started.\n");
        std::string newPassword = TerminalUI::get_password_input("Enter new master password: ");
        std::string confirmPassword = TerminalUI::get_password_input("Confirm master password: ");
        setupPassword(newPassword, confirmPassword, encryption_utils::getDefault());
    } else {
        TerminalUI::display_message("Please enter your master password to continue.");
    }
}

int TerminalUIManager::show() {
    try {
        if (isLoggedIn) return runMenuLoop();  // just created in initialize()
        if (!vault->exists()) return 1;        // setup was aborted

        for (int attempts = 1; attempts <= kMaxLoginAttempts; ++attempts) {
            std::string password = TerminalUI::get_password_input("Enter master password: ");
            if (login(password)) return runMenuLoop();
            TerminalUI::display_message("Invalid password! Try again.", true);
        }
        TerminalUI::display_message("Too many failed attempts. Exiting...", true);
        return 1;
    } catch (const std::exception& e) {
        showMessage("Error", e.what(), true);
        return 1;
    }
}

bool TerminalUIManager::login(const std::string& password) {
    try {
        TerminalUI::display_message("Unlocking...");
        isLoggedIn = vault->unlock(password);
        if (isLoggedIn) TerminalUI::display_message(syncStatusText());
        return isLoggedIn;
    } catch (const std::exception& e) {
        showMessage("Error", e.what(), true);
        return false;
    }
}

bool TerminalUIManager::setupPassword(const std::string& newPassword,
                                      const std::string& confirmPassword,
                                      CipherAlg encryptionType) {
    try {
        if (newPassword.empty()) {
            showMessage("Error", "Password cannot be empty!", true);
            return false;
        }
        if (newPassword != confirmPassword) {
            showMessage("Error", "Passwords do not match!", true);
            return false;
        }
        vault->create(newPassword, encryptionType);
        isLoggedIn = true;
        showMessage("Success", "Vault created. " + syncStatusText());
        return true;
    } catch (const std::exception& e) {
        showMessage("Error", e.what(), true);
        return false;
    }
}

bool TerminalUIManager::addCredential(const std::string& platform,
                                      const std::string& username,
                                      const std::string& password,
                                      std::optional<CipherAlg> encryptionType) {
    if (!isLoggedIn) return false;
    if (safeAddCredential(platform, username, password, encryptionType)) {
        showMessage("Success", "Credentials saved. " + syncStatusText());
        return true;
    }
    showMessage("Error", "Failed to add credentials!", true);
    return false;
}

void TerminalUIManager::viewCredential(const std::string& platform) {
    if (!isLoggedIn) return;
    try {
        auto credsOpt = safeGetCredentials(platform);
        if (!credsOpt) {
            if (vault->lastSyncStatus() == VaultService::SyncStatus::Offline && !ConfigManager::getInstance().getConfig().localCopy)
                showMessage("Error", syncStatusText(), true);
            else
                showMessage("Info", "No credentials found for " + platform);
            return;
        }
        const Credential& credentials = *credsOpt;

        TerminalUI::clear_screen();
        TerminalUI::display_message("Credentials for " + credentials.platform + ":");
        TerminalUI::display_message("Username: " + credentials.username);
        TerminalUI::display_message("Password: " + credentials.password);
        if (ConfigManager::getInstance().getShowEncryptionInCredentials())
            TerminalUI::display_message(std::string("Encryption: ") + encryption_utils::getDisplayName(credentials.alg));

        TerminalUI::display_message("\nOptions:");
        TerminalUI::display_message("1. Copy password to clipboard");
        TerminalUI::display_message("2. Update password");
        TerminalUI::display_message("3. Return to main menu");

        std::string choice = TerminalUI::get_text_input("\nEnter your choice (1-3): ");

        if (choice == "1") {
            try {
                if (ClipboardManager::getInstance().isAvailable()) {
                    ClipboardManager::getInstance().copyToClipboard(credentials.password);
                    TerminalUI::display_message("Password copied to clipboard for 30 seconds.");
                } else {
                    TerminalUI::display_message("\nClipboard functionality not available on this system.");
                }
            } catch (const ClipboardError& e) {
                TerminalUI::display_message("\nFailed to copy password to clipboard: " + std::string(e.what()));
            }
        } else if (choice == "2") {
            std::string newPassword = TerminalUI::get_password_input("\nEnter new password: ");
            if (newPassword.empty()) {
                TerminalUI::display_message("Password cannot be empty.", true);
                return;
            }
            updateCredential(credentials.platform, credentials.username, newPassword);
        }
    } catch (const std::exception& e) {
        showMessage("Error", e.what(), true);
    }
}

bool TerminalUIManager::deleteCredential(const std::string& platform) {
    if (!isLoggedIn) return false;
    std::string confirmation =
        TerminalUI::get_text_input("Are you sure you want to delete credentials for " + platform + "? (y/n): ");
    if (confirmation != "y" && confirmation != "Y") return false;
    bool deleteSuccess = safeDeleteCredential(platform);
    if (deleteSuccess)
        showMessage("Success", "Credentials deleted. " + syncStatusText());
    else
        showMessage("Error", "No credentials found for " + platform, true);
    return deleteSuccess;
}

void TerminalUIManager::showMessage(const std::string& title, const std::string& message, bool isError) {
    // In terminal UI, we don't need to show the title separately
    TerminalUI::display_message(message, isError);
    if (isError) std::cerr << title << ": " << message << std::endl;
}

int TerminalUIManager::runMenuLoop() {
    if (!isLoggedIn) return 1;

    int menuChoice = 0;
    do {
        menuChoice = TerminalUI::display_menu();
        switch (menuChoice) {
            case 1: {
                std::string newPassword = TerminalUI::get_password_input("Enter new master password: ");
                std::string confirmPassword = TerminalUI::get_password_input("Confirm new master password: ");
                if (newPassword.empty() || newPassword != confirmPassword)
                    showMessage("Error", "Passwords are empty or do not match!", true);
                else if (safeChangeMasterPassword(newPassword))
                    showMessage("Success", "Master password changed. " + syncStatusText());
                else
                    showMessage("Error", "Failed to change master password!", true);
                TerminalUI::pause_screen();
                TerminalUI::clear_screen();
                break;
            }
            case 2: {
                std::string platform = TerminalUI::get_text_input("Enter platform name: ");
                std::string username = TerminalUI::get_text_input("Enter username: ");
                std::string password = TerminalUI::get_password_input("Enter password: ");
                addCredential(platform, username, password, chooseCipher("\nEncryption for this entry:"));
                TerminalUI::pause_screen();
                TerminalUI::clear_screen();
                break;
            }
            case 3: {
                std::string platform = TerminalUI::get_text_input("Enter platform name to view: ");
                viewCredential(platform);
                TerminalUI::pause_screen();
                TerminalUI::clear_screen();
                break;
            }
            case 4: {
                std::string platform = TerminalUI::get_text_input("Enter platform name to delete: ");
                deleteCredential(platform);
                TerminalUI::pause_screen();
                TerminalUI::clear_screen();
                break;
            }
            case 5: {
                std::vector<std::string> platforms = safeGetPlatforms();
                TerminalUI::clear_screen();
                TerminalUI::display_message("Available platforms:  [" + syncStatusText() + "]");
                if (platforms.empty()) {
                    TerminalUI::display_message("No platforms found.");
                } else {
                    for (const auto& platform : platforms) TerminalUI::display_message("• " + platform);
                }
                TerminalUI::pause_screen();
                TerminalUI::clear_screen();
                break;
            }
            default:
                // Invalid menu choice - do nothing, the loop will continue
                break;
        }
    } while (menuChoice != 0);

    vault->lock();
    return 0;
}

bool TerminalUIManager::updateCredential(const std::string& platform,
                                         const std::string& username,
                                         const std::string& password,
                                         std::optional<CipherAlg> encryptionType) {
    if (!isLoggedIn) {
        showMessage("Error", "You must log in first.", true);
        return false;
    }
    bool updateSuccess = UIManager::updateCredential(platform, username, password, encryptionType);
    if (updateSuccess)
        showMessage("Success", "Credentials updated. " + syncStatusText());
    else
        showMessage("Error", "Failed to update credentials!", true);
    return updateSuccess;
}
