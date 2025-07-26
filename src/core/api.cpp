#include "./api.h"
#include "./encryption.h" // Include the encryption header with EncryptionError
#include "../config/GlobalConfig.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <algorithm> // For std::replace
#include <optional>
#include <filesystem>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include "../crypto/encryption_factory.h"

// Use the appropriate filesystem library
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

// Method implementations

void CredentialsManager::createEncryptor(EncryptionType type, const std::string& password) {
    // Store encryption parameters
    encryptionType = type;
    currentMasterPassword = password;
    
    // Get LFSR parameters from config
    lfsrTaps = ConfigManager::getInstance().getLfsrTaps();
    lfsrInitState = ConfigManager::getInstance().getLfsrInitState();
    
    // Create new encryptor through factory
    encryptor = EncryptionFactory::create(type, lfsrTaps, lfsrInitState);
    if (encryptor) {
        encryptor->setMasterPassword(password);
    }
}

CredentialsManager::CredentialsManager(const std::string& dataPath, EncryptionType encryptionType)
        : dataPath(dataPath), storage(nullptr) {
    // Initialize storage
    storage = new JsonStorage(dataPath);
    
    // Initialize encryption with default parameters
    createEncryptor(encryptionType, "");
}

CredentialsManager::~CredentialsManager() {
    // unique_ptr will automatically delete the encryptor
    delete storage;
}

bool CredentialsManager::login(const std::string& password) {
    if (password.empty()) {
        return false;
    }
    
    // Try to verify the password
    try {
        std::string encryptedMaster = storage->getMasterPassword();
        if (encryptedMaster.empty()) {
            // No master password set yet, create one with the provided password
            currentMasterPassword = password;
            createEncryptor(encryptionType, password);
            return true;
        }
        
        // The stored value is in the format: salt$encrypted_verification_token
        size_t delimiter = encryptedMaster.find('$');
        if (delimiter == std::string::npos) {
            return false;
        }
        
        std::string salt = encryptedMaster.substr(0, delimiter);
        std::string encryptedToken = encryptedMaster.substr(delimiter + 1);
        
        // Get the default encryption type for master password
        EncryptionType masterEncType = ConfigManager::getInstance().getDefaultEncryption();
        const auto& configTaps = ConfigManager::getInstance().getLfsrTaps();
        const auto& configInitState = ConfigManager::getInstance().getLfsrInitState();
        
        // Create a temporary encryptor for verification using master password
        auto tempEncryptor = EncryptionFactory::createForMasterPassword(
            masterEncType, password, configTaps, configInitState);
        if (!tempEncryptor) {
            return false;
        }
        
        // Try to decrypt the verification token with the provided password
        tempEncryptor->setMasterPassword(password);
        std::string decryptedToken = tempEncryptor->decrypt(encryptedToken);
        
        // If decryption was successful and the token has the expected format
        if (!decryptedToken.empty() && decryptedToken.find("verify_") == 0) {
            // Password is correct, update our main encryptor
            currentMasterPassword = password;
            createEncryptor(encryptionType, password);
            return true;
        }
    } catch (const std::exception& e) {
        std::cerr << "Login failed: " << e.what() << std::endl;
    }
    return false; 
}

bool CredentialsManager::updatePassword(const std::string& newPassword) {
    try {
        if (newPassword.empty()) {
            std::cerr << "Error: Empty password provided\n";
            return false;
        }
        
        // Always use the default encryption type from config for master password
        EncryptionType masterEncType = ConfigManager::getInstance().getDefaultEncryption();
        const auto& configTaps = ConfigManager::getInstance().getLfsrTaps();
        const auto& configInitState = ConfigManager::getInstance().getLfsrInitState();
        
        // Create a new encryptor with the default encryption type and new password
        auto masterEncryptor = EncryptionFactory::createForMasterPassword(
            masterEncType, newPassword, configTaps, configInitState);
            
        if (!masterEncryptor) {
            throw std::runtime_error("Failed to create encryptor for type: " + 
                                  std::to_string(static_cast<int>(masterEncType)));
        }
        
        // Generate a random salt
        unsigned char salt[16];
        if (RAND_bytes(salt, sizeof(salt)) != 1) {
            throw std::runtime_error("Failed to generate random salt");
        }
        
        // Create a verification token (don't store the actual password)
        std::string verificationToken = "verify_" + std::to_string(std::time(nullptr));
        
        // Encrypt the verification token with the new password
        std::string encryptedToken = masterEncryptor->encrypt(verificationToken);
        
        // Store the salt and encrypted token
        std::string saltStr(reinterpret_cast<const char*>(salt), sizeof(salt));
        return storage->updateMasterPassword(saltStr + "$" + encryptedToken);
    } catch (const EncryptionError& e) {
        std::cerr << "Encryption error during password update: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Exception during password update: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::addCredentials(const std::string& platform, const std::string& user, 
                                      const std::string& pass, std::optional<EncryptionType> encryptionType) {
    if (platform.empty() || user.empty() || pass.empty()) {
        return false;
    }
    
    // Use provided encryption type or default to instance type
    EncryptionType credEncType = encryptionType.value_or(this->encryptionType);
    
    try {
        // Use the factory to get the right encryptor for this credential
        auto credEncryptor = EncryptionFactory::createForMasterPassword(
            credEncType, 
            currentMasterPassword,
            ConfigManager::getInstance().getLfsrTaps(),
            ConfigManager::getInstance().getLfsrInitState()
        );
        
        if (!credEncryptor) {
            throw std::runtime_error("Failed to create encryptor for type: " + std::to_string(static_cast<int>(credEncType)));
        }
        
        // Set the master password for this encryptor
        credEncryptor->setMasterPassword(currentMasterPassword);
        
        // Encrypt the password
        std::string encryptedPass = credEncryptor->encrypt(pass);
        std::string encryptedUser = credEncryptor->encrypt(user);

        // Store the credentials with encryption type
        storage->addCredentials(platform, encryptedUser, encryptedPass, static_cast<int>(credEncType));

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error adding credentials: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::deleteCredentials(const std::string& platform) {
    try {
        return storage->deleteCredentials(platform);
    } catch (const std::exception& e) {
        std::cerr << "Error deleting credentials: " << e.what() << std::endl;
        return false;
    }
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
            std::unique_ptr<IEncryption> tempEncryptor;
            IEncryption* currentEncryptor = encryptor.get();
            
            if (credEncType != encryptor->getType()) {
                const auto& configTaps = ConfigManager::getInstance().getLfsrTaps();
                const auto& configInitState = ConfigManager::getInstance().getLfsrInitState();
                // Use the factory to create the correct encryptor type
                tempEncryptor = EncryptionFactory::createForMasterPassword(
                    credEncType,
                    currentMasterPassword,
                    configTaps,
                    configInitState
                );
                currentEncryptor = tempEncryptor.get();
            }
            
            try {
                // For AES, the decrypt method handles the salt and IV extraction
                std::string username = currentEncryptor->decrypt(encryptedCredentials[0]);
                std::string password = currentEncryptor->decrypt(encryptedCredentials[1]);
                decryptedCredentials.insert(decryptedCredentials.begin(), username);
                decryptedCredentials.insert(decryptedCredentials.begin() + 1, password);
            } catch (const EncryptionError& e) {
                std::cerr << "Decryption error: " << e.what() ; 
                return std::vector<std::string>();
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
        createEncryptor(type, currentMasterPassword);
    }
}

std::vector<std::string> CredentialsManager::getAllPlatforms() const {
    if (!storage) {
        throw std::runtime_error("Storage not initialized");
    }
    
    try {
        return storage->getAllPlatforms();
    } catch (const std::exception& e) {
        std::cerr << "Error retrieving platforms: " << e.what() << std::endl;
        return {};
    }
}
