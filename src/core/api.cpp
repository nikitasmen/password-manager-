#include "./api.h"
#include "./encryption.h" // Include the encryption header with EncryptionError
#include "../config/GlobalConfig.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <algorithm> // For std::replace
#include <optional>

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

CredentialsManager::CredentialsManager(const std::string& dataPath, EncryptionType encryptionType) 
    : dataPath(dataPath), encryptionType(encryptionType), currentMasterPassword("") {
    // Dynamically allocate memory for encryptor and storage
    // Get LFSR settings from ConfigManager to ensure we're using the current settings
    const auto& configTaps = ConfigManager::getInstance().getLfsrTaps();
    const auto& configInitState = ConfigManager::getInstance().getLfsrInitState();
    
    // Update global variables to match config (in case they're out of sync)
    taps = configTaps;
    init_state = configInitState;
    
    // Use the settings from ConfigManager
    encryptor = new Encryption(encryptionType, configTaps, configInitState, currentMasterPassword);
    storage = new JsonStorage(dataPath);
}

CredentialsManager::~CredentialsManager() {
    // Clean up allocated memory
    if (encryptor) {
        delete encryptor;
        encryptor = nullptr;
    }
    
    if (storage) {
        delete storage;
        storage = nullptr;
    }
}

bool CredentialsManager::login(const std::string& password) {
    try {
        if (password.empty()) {
            std::cerr << "Error: Empty password provided\n";
            return false;
        }
        
        std::string storedPassword = storage->getMasterPassword();
        bool passwordMatched = false;

        // Try with current settings only
        try {
            std::string correct = encryptor->decryptWithSalt(storedPassword);
            if (correct == password) {
                passwordMatched = true;
            }
        } catch (const std::exception& e) {
            std::cerr << "Login with current settings failed: " << e.what() << std::endl;
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
        // Always use encryptWithSalt (it will handle salt logic internally)
        std::string passwordToStore = encryptor->encryptWithSalt(newPassword);
        return storage->updateMasterPassword(passwordToStore);
    } catch (const EncryptionError& e) {
        std::cerr << "Encryption error during password update: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Exception during password update: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::addCredentials(const std::string& platform, const std::string& user, const std::string& pass,
                               std::optional<EncryptionType> encryptionType) {
    try {
        // Use specified encryption algorithm or fall back to the current global setting
        EncryptionType actualEncryptionType = encryptionType.value_or(this->encryptionType);
        
        // Create a temporary encryptor with the desired algorithm if needed
        Encryption* currentEncryptor = encryptor;
        std::unique_ptr<Encryption> tempEncryptor;
        
        // If requested algorithm is different from current, create a temporary encryptor
        if (actualEncryptionType != encryptor->getAlgorithm()) {
            tempEncryptor = std::make_unique<Encryption>(actualEncryptionType, taps, init_state, currentMasterPassword);
            currentEncryptor = tempEncryptor.get();
        }
        
        // Encrypt with the selected algorithm
        std::string encryptedUser = currentEncryptor->encryptWithSalt(user);
        std::string encryptedPass = currentEncryptor->encryptWithSalt(pass);
        
        // Store the encryption type as an integer
        int encType = static_cast<int>(actualEncryptionType);
        
        return storage->addCredentials(platform, encryptedUser, encryptedPass, encType);
    } catch (const std::exception& e) {
        std::cerr << "Error adding credentials: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::deleteCredentials(const std::string& platform) {
    try {
        if (platform.empty()) {
            std::cerr << "Error: Empty platform name provided\n";
            return false;
        }
        
        return storage->deleteCredentials(platform);
    } catch (const std::exception& e) {
        std::cerr << "Exception while deleting credentials: " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::string> CredentialsManager::getAllPlatforms() {
    return storage->getAllPlatforms();
}

std::vector<std::string> CredentialsManager::getCredentials(const std::string& platform) {
    try {
        if (platform.empty()) {
            std::cerr << "Error: Empty platform name provided\n";
            return std::vector<std::string>();
        }
        
        std::vector<std::string> encryptedCredentials = storage->getCredentials(platform);
        std::vector<std::string> decryptedCredentials;
        
        // Check if we have the minimum required data (username and password)
        if (encryptedCredentials.size() >= 2) {
            // Get encryption type if available (3rd element)
            EncryptionType credEncType = encryptionType; // Default to current
            if (encryptedCredentials.size() >= 3) {
                // Convert string to EncryptionType
                try {
                    int encTypeValue = std::stoi(encryptedCredentials[2]);
                    credEncType = static_cast<EncryptionType>(encTypeValue);
                } catch (...) {
                    // Use default if conversion fails
                }
                
                // Add the encryption type to the result
                decryptedCredentials.push_back(encryptedCredentials[2]);
            } else {
                // Add default encryption type if not specified
                decryptedCredentials.push_back(std::to_string(static_cast<int>(credEncType)));
            }
            
            // Create a temporary encryptor with the correct algorithm if needed
            Encryption* currentEncryptor = encryptor;
            std::unique_ptr<Encryption> tempEncryptor;
            
            // If credential's encryption type is different from current, create a temporary encryptor
            if (credEncType != encryptor->getAlgorithm()) {
                tempEncryptor = std::make_unique<Encryption>(credEncType, taps, init_state, currentMasterPassword);
                currentEncryptor = tempEncryptor.get();
            }
            
            try {
                // Use salt-aware decryption with the appropriate algorithm
                decryptedCredentials.insert(decryptedCredentials.begin(), 
                                          currentEncryptor->decryptWithSalt(encryptedCredentials[0]));
                decryptedCredentials.insert(decryptedCredentials.begin() + 1, 
                                          currentEncryptor->decryptWithSalt(encryptedCredentials[1]));
            } catch (const EncryptionError& e) {
                // Fallback to legacy decryption if salt-aware fails
                try {
                    // Keep only the encryption type
                    std::string encType = decryptedCredentials.back();
                    decryptedCredentials.clear();
                    decryptedCredentials.push_back(currentEncryptor->decrypt(encryptedCredentials[0]));
                    decryptedCredentials.push_back(currentEncryptor->decrypt(encryptedCredentials[1]));
                    decryptedCredentials.push_back(encType);
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
        std::string storedPassword = storage->getMasterPassword();
        return !storedPassword.empty();
    } catch (const std::exception& e) {
        std::cerr << "Exception checking master password: " << e.what() << std::endl;
        return false;
    }
}

void CredentialsManager::setEncryptionType(EncryptionType type) {
    encryptionType = type;
    if (encryptor) {
        encryptor->setAlgorithm(type);
    }
    g_encryption_type = type; // Update global setting
}


