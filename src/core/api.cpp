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

// Method implementations

CredentialsManager::CredentialsManager(const std::string& dataPath, EncryptionType encryptionType) 
    : dataPath(dataPath), 
      encryptionType(encryptionType), 
      storage(std::make_unique<JsonStorage>(dataPath)),
      encryptor(nullptr),  // Initialize to nullptr - will be created during login
      isLoggedIn(false) {
    
    // Don't create encryption instance here - it will be created during login
    // when we have the master password available
}

CredentialsManager::~CredentialsManager() = default;

bool CredentialsManager::login(const std::string& password) {
    try {
        if (password.empty()) {
            throw std::runtime_error("Password cannot be empty");
        }
        
        // Store the master password for use in encryption operations
        masterPassword = password;
        
        // Create or update the encryption instance with the master password
        const auto& configTaps = ConfigManager::getInstance().getLfsrTaps();
        const auto& configInitState = ConfigManager::getInstance().getLfsrInitState();
        encryptor = EncryptionFactory::create(encryptionType, configTaps, configInitState, password);
        
        isLoggedIn = true;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Login failed: " << e.what() << std::endl;
        isLoggedIn = false;
        masterPassword.clear();
        return false;
    }
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
        auto masterEncryptor = EncryptionFactory::create(masterEncType, configTaps, configInitState, newPassword);
        std::string passwordToStore;
            if (masterEncType == EncryptionType::LFSR) {
                passwordToStore = masterEncryptor->encryptWithSalt(newPassword);
            } else {
                passwordToStore = masterEncryptor->encrypt(newPassword);
            }
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
        if (!isLoggedIn || masterPassword.empty()) {
            std::cerr << "Error: Must be logged in to add credentials" << std::endl;
            return false;
        }
        
        if (platform.empty() || user.empty() || pass.empty()) {
            std::cerr << "Error: Platform, user, and password cannot be empty" << std::endl;
            return false;
        }
        
        EncryptionType actualEncryptionType = encryptionType.value_or(this->encryptionType);
        int encType = static_cast<int>(actualEncryptionType);
        std::string extraInfo = "";
        
        // Create encryptor for the specific type if different from current
        std::unique_ptr<Encryption> targetEncryptor;
        if (actualEncryptionType != this->encryptionType) {
            const auto& configTaps = ConfigManager::getInstance().getLfsrTaps();
            const auto& configInitState = ConfigManager::getInstance().getLfsrInitState();
            targetEncryptor = EncryptionFactory::create(actualEncryptionType, configTaps, configInitState, masterPassword);
            
            // Handle RSA key generation if needed
            if (actualEncryptionType == EncryptionType::RSA) {
                auto manager = dynamic_cast<EncryptionManager*>(targetEncryptor.get());
                if (manager) {
                    auto keyPair = manager->generateRsaKeys();
                    extraInfo = keyPair.first + "\n-----PRIVATE KEY-----\n" + keyPair.second;
                }
            }
        } else {
            targetEncryptor = std::unique_ptr<Encryption>(nullptr); // Use existing encryptor
        }
        
        // Use the appropriate encryptor
        Encryption* activeEncryptor = targetEncryptor ? targetEncryptor.get() : encryptor.get();
        
        // Encrypt credentials using the selected encryptor
        std::string encryptedUser = activeEncryptor->encryptWithSalt(user);
        std::string encryptedPass = activeEncryptor->encryptWithSalt(pass);
        
        return storage->addCredentials(platform, encryptedUser, encryptedPass, encType, extraInfo);
        
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
        if (!isLoggedIn || masterPassword.empty()) {
            std::cerr << "Error: Must be logged in to retrieve credentials" << std::endl;
            return {};
        }
        
        if (platform.empty()) {
            std::cerr << "Error: Platform name cannot be empty" << std::endl;
            return {};
        }
        
        auto record = storage->getCredentials(platform);
        if (record.size() < 3) {
            std::cerr << "Error: Invalid credential record for platform: " << platform << std::endl;
            return {};
        }
        
        std::string encryptedUser = record[0];
        std::string encryptedPass = record[1];
        int encType = std::stoi(record[2]);
        std::string extraInfo = (record.size() > 3) ? record[3] : "";
        EncryptionType type = static_cast<EncryptionType>(encType);
        
        // Create decryptor for the specific type
        const auto& configTaps = ConfigManager::getInstance().getLfsrTaps();
        const auto& configInitState = ConfigManager::getInstance().getLfsrInitState();
        std::unique_ptr<Encryption> decryptor;
        
        if (type == EncryptionType::RSA) {
            // Parse public and private key from extraInfo
            size_t split = extraInfo.find("\n-----PRIVATE KEY-----\n");
            if (split == std::string::npos) throw EncryptionError("RSA key info missing");
            std::string pubKey = extraInfo.substr(0, split);
            std::string privKey = extraInfo.substr(split + 24); // length of delimiter
            
            decryptor = EncryptionFactory::create(type, configTaps, configInitState, masterPassword, pubKey, privKey);
        } else {
            decryptor = EncryptionFactory::create(type, configTaps, configInitState, masterPassword);
        }
        
        // Decrypt credentials using the appropriate encryptor
        std::string user = decryptor->decryptWithSalt(encryptedUser);
        std::string pass = decryptor->decryptWithSalt(encryptedPass);
        
        return {user, pass, record[2]};
    } catch (const std::exception& e) {
        std::cerr << "Error getting credentials: " << e.what() << std::endl;
        return {};
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
    this->encryptionType = type;
    
    // If logged in, update the encryptor with the new type
    if (isLoggedIn && !masterPassword.empty()) {
        try {
            const auto& configTaps = ConfigManager::getInstance().getLfsrTaps();
            const auto& configInitState = ConfigManager::getInstance().getLfsrInitState();
            encryptor = EncryptionFactory::create(type, configTaps, configInitState, masterPassword);
        } catch (const std::exception& e) {
            std::cerr << "Warning: Failed to update encryptor with new type: " << e.what() << std::endl;
        }
    }
}


