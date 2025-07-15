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

        std::string storedPassword = storage.getMasterPassword();
        
        if (storedPassword.empty()) {
            std::cerr << "No existing password found. Please create one using the setup tool.\n";
            return false;
        }
        
        bool passwordMatched = false;
        
        // Handle simple case: plaintext password (for initial setup)
        if (storedPassword == password) {
            passwordMatched = true;
        } else {
            // Try the salt-based method first
            try {
                std::string correct = encryptor.decryptWithSalt(storedPassword);
                if (password == correct) {
                    passwordMatched = true;
                }
            } catch (const std::exception& e) {
                std::cerr << "Salt-based decryption failed: " << e.what() << std::endl;
                
                // Try legacy method only if salt method fails
                try {
                    std::string correct = encryptor.decrypt(storedPassword);
                    if (password == correct) {
                        passwordMatched = true;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Legacy decryption failed: " << e.what() << std::endl;
                }
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

        std::string passwordToStore;
        
        // For very simple cases, just save plaintext
        if (newPassword.length() <= 3) {
            passwordToStore = newPassword;
            std::cout << "Using plain text storage for short passwords" << std::endl;
        } else {
            // Use enhanced encryption with salt for longer passwords
            passwordToStore = encryptor.encryptWithSalt(newPassword);
            std::cout << "Password encrypted with salt" << std::endl;
        }
        
        bool result = storage.updateMasterPassword(passwordToStore);
        
        // Now let's verify we can read it back
        try {
            bool verifyResult = login(newPassword);
            if (!verifyResult) {
                std::cerr << "Warning: Password verification failed" << std::endl;
            } else {
                std::cout << "Password verification successful" << std::endl;
            }
        } catch (...) {
            // Ignore verification errors
        }
        
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

        // Use enhanced encryption with salt
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
                std::cerr << "Encryption error while decrypting credentials: " << e.what() << std::endl;
                
                // Fallback to legacy decryption if salt-aware fails
                try {
                    decryptedCredentials.clear();
                    decryptedCredentials.push_back(encryptor.decrypt(encryptedCredentials[0]));
                    decryptedCredentials.push_back(encryptor.decrypt(encryptedCredentials[1]));
                } catch (const EncryptionError& e2) {
                    std::cerr << "Legacy decryption also failed: " << e2.what() << std::endl;
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


