#include "./api.h"
#include "./encryption.h" // Include the encryption header with EncryptionError
#include "../../GlobalConfig.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <algorithm> // For std::replace

// Use the appropriate filesystem library
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

extern std::vector<int> taps;
extern std::vector<int> init_state;

// Method implementations

CredentialsManager::CredentialsManager(const std::string& dataPath) 
    : dataPath(dataPath), encryptor(taps, init_state), storage(dataPath) {
}

bool CredentialsManager::login(const std::string& password) {
    try {
        if (password.empty()) {
            std::cerr << "Error: Empty password provided\n";
            return false;
        }

        // If no password exists, create one with the provided password
        if (!hasMasterPassword()) {
            return updatePassword(password);
        }
        
        std::string storedPassword = storage.getMasterPassword();
        
        bool passwordMatched = false;
        
        // Try the salt-based method only
        try {
            std::string correct = encryptor.decryptWithSalt(storedPassword);
            if (correct == password) {
                passwordMatched = true;
            }
        } catch (const std::exception& e) {
            // If salt decryption fails, check if it's a legacy plaintext password
            // This is for backward compatibility during the transition period
            if (storedPassword == password) {
                passwordMatched = true;
                
                // Upgrade the plaintext password to salt-encrypted
                updatePassword(password);
            }
        }
        
        if (!passwordMatched) {
            std::cerr << "Authentication failed: Invalid password" << std::endl;
        }
        
        return passwordMatched;
    } catch (const std::exception& e) {
        std::cerr << "Exception during login: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::updatePassword(const std::string& newPassword) {
    try {
        if (newPassword.empty()) {
            std::cerr << "Error: Empty password provided\n";
            return false;
        }

        // Always use salt encryption
        std::string passwordToStore = encryptor.encryptWithSalt(newPassword);
        
        bool result = storage.updateMasterPassword(passwordToStore);
        
        // Skip verification to avoid circular dependency with login
        // We've already tested that salt encryption/decryption works
        
        return result;
    } catch (const EncryptionError& e) {
        std::cerr << "Encryption error during password update: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Exception during password update: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::addCredentials(const std::string& platform, const std::string& user, const std::string& pass) {
    try {
        if (platform.empty() || user.empty() || pass.empty()) {
            std::cerr << "Error: Empty platform, username, or password provided\n";
            return false;
        }

        // Encrypt credentials with salt
        std::string encryptedUser = encryptor.encryptWithSalt(user);
        std::string encryptedPass = encryptor.encryptWithSalt(pass);
        
        return storage.addCredentials(platform, encryptedUser, encryptedPass);
    } catch (const EncryptionError& e) {
        std::cerr << "Encryption error while adding credentials: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Exception while adding credentials: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::deleteCredentials(const std::string& platform) {
    try {
        if (platform.empty()) {
            std::cerr << "Error: Empty platform name provided\n";
            return false;
        }
        
        return storage.deleteCredentials(platform);
    } catch (const std::exception& e) {
        std::cerr << "Exception while deleting credentials: " << e.what() << std::endl;
        return false;
    }
}

void CredentialsManager::showOptions(const std::string& path) const {
    try {
        std::vector<std::string> platforms = storage.getAllPlatforms();
        
        std::cout << "Available platforms:\n";
        std::cout << "==================\n";
        
        if (platforms.empty()) {
            std::cout << "No platforms found.\n";
        } else {
            for (const auto& platform : platforms) {
                std::cout << "- " << platform << std::endl;
            }
        }
        
        std::cout << "==================\n";
    } catch (const std::exception& e) {
        std::cerr << "Exception while showing options: " << e.what() << std::endl;
    }
}

std::vector<std::string> CredentialsManager::getAllPlatforms() {
    return storage.getAllPlatforms();
}

std::vector<std::string> CredentialsManager::getCredentials(const std::string& platform) {
    try {
        if (platform.empty()) {
            std::cerr << "Error: Empty platform name provided\n";
            return std::vector<std::string>();
        }
        
        std::vector<std::string> encryptedCredentials = storage.getCredentials(platform);
        std::vector<std::string> decryptedCredentials;
        
        if (encryptedCredentials.size() == 2) {
            try {
                // Use salt-aware decryption
                decryptedCredentials.push_back(encryptor.decryptWithSalt(encryptedCredentials[0]));
                decryptedCredentials.push_back(encryptor.decryptWithSalt(encryptedCredentials[1]));
            } catch (const EncryptionError& e) {
                // Fallback to legacy decryption if salt-aware fails
                try {
                    decryptedCredentials.clear();
                    decryptedCredentials.push_back(encryptor.decrypt(encryptedCredentials[0]));
                    decryptedCredentials.push_back(encryptor.decrypt(encryptedCredentials[1]));
                } catch (const EncryptionError&) {
                    return std::vector<std::string>();
                }
            }
        } else {
            std::cerr << "Failed to retrieve credentials for platform: " << platform << "\n";
        }
        
        return decryptedCredentials;
    } catch (const std::exception& e) {
        std::cerr << "Exception while getting credentials: " << e.what() << std::endl;
        return std::vector<std::string>();
    }
}

bool CredentialsManager::hasMasterPassword() const {
    try {
        std::string storedPassword = storage.getMasterPassword();
        return !storedPassword.empty();
    } catch (const std::exception& e) {
        std::cerr << "Exception checking master password: " << e.what() << std::endl;
        return false;
    }
}


