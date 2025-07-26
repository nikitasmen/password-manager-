#include "./api.h"

#include "../config/GlobalConfig.h"
#include "../crypto/lfsr_encryption.h"
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
    encryptionType = type;
    currentMasterPassword = password;
    lfsrTaps = ConfigManager::getInstance().getLfsrTaps();
    lfsrInitState = ConfigManager::getInstance().getLfsrInitState();
    
    encryptor = EncryptionFactory::createForMasterPassword(type, password, lfsrTaps, lfsrInitState);
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
            // No master password is set, so login should fail.
            return false;
        }
        
        // The stored value can be in one of these formats:
        // 1. salt$encrypted_verification_token (old format)
        // 2. salt:encrypted_verification_token (new format from migration)
        size_t delimiter = encryptedMaster.find('$');
        if (delimiter == std::string::npos) {
            // Try with colon as delimiter (new format)
            delimiter = encryptedMaster.find(':');
            if (delimiter == std::string::npos) {
                std::cerr << "Invalid format for stored master password" << std::endl;
                return false;
            }
        }
        
        std::string salt = encryptedMaster.substr(0, delimiter);
        std::string encryptedToken = encryptedMaster.substr(delimiter + 1);
        
        // Get the default encryption type for master password
        EncryptionType masterEncType = ConfigManager::getInstance().getDefaultEncryption();
        const auto& configTaps = ConfigManager::getInstance().getLfsrTaps();
        const auto& configInitState = ConfigManager::getInstance().getLfsrInitState();
        
        // Create a temporary encryptor for verification using master password
        std::unique_ptr<IEncryption> tempEncryptor;

        if (masterEncType == EncryptionType::LFSR) {
            // For LFSR, we must create the encryptor with the salt
            tempEncryptor = std::make_unique<LFSREncryption>(configTaps, configInitState, salt);
        } else {
            // For other types, the factory is sufficient
            tempEncryptor = EncryptionFactory::createForMasterPassword(
                masterEncType,
                password,
                configTaps,
                configInitState
            );
        }

        if (!tempEncryptor) {
            return false;
        }
        tempEncryptor->setMasterPassword(password);

        // Decrypt the token. For LFSR, the salt is already in the state.
        // For AES, the salt is part of the encrypted data.
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
        
        // Generate a random salt
        unsigned char saltBytes[16];
        if (RAND_bytes(saltBytes, sizeof(saltBytes)) != 1) {
            throw std::runtime_error("Failed to generate random salt");
        }
        std::string saltStr(reinterpret_cast<const char*>(saltBytes), sizeof(saltBytes));
        
        // Create a verification token (don't store the actual password)
        std::string verificationToken = "verify_" + std::to_string(std::time(nullptr));
        
        std::unique_ptr<IEncryption> masterEncryptor;
        
        if (masterEncType == EncryptionType::LFSR) {
            // For LFSR, manually create the encryptor with the generated salt
            masterEncryptor = std::make_unique<LFSREncryption>(
                configTaps, configInitState, saltStr);
            masterEncryptor->setMasterPassword(newPassword);
        } else {
            // For other encryption types, use the factory
            masterEncryptor = EncryptionFactory::createForMasterPassword(
                masterEncType, newPassword, configTaps, configInitState);
        }
        
        if (!masterEncryptor) {
            throw std::runtime_error("Failed to create encryptor for type: " + 
                                  std::to_string(static_cast<int>(masterEncType)));
        }
        
        // Encrypt the verification token with the new password and salt
        std::string encryptedToken = masterEncryptor->encrypt(verificationToken);
        
        // Store the salt and encrypted token
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

    if (currentMasterPassword.empty()) {
        if (hasMasterPassword()) {
            throw std::runtime_error("User not logged in. Please log in before adding credentials.");
        } else {
            throw std::runtime_error("Master password not set. Please set up a master password first.");
        }
    }
    
    // Use provided encryption type or default to instance type
    EncryptionType credEncType = encryptionType.value_or(this->encryptionType);
    
    try {
        auto credEncryptor = EncryptionFactory::createForMasterPassword(
            credEncType, 
            currentMasterPassword,
            ConfigManager::getInstance().getLfsrTaps(),
            ConfigManager::getInstance().getLfsrInitState()
        );

        if (!credEncryptor) {
            throw std::runtime_error("Failed to create encryptor for type: " + std::to_string(static_cast<int>(credEncType)));
        }

        credEncryptor->setMasterPassword(currentMasterPassword);

        std::string encryptedUser, encryptedPass;
        if (auto saltedEncryptor = dynamic_cast<ISaltedEncryption*>(credEncryptor.get())) {
            std::vector<std::string> plaintexts = {user, pass};
            std::vector<std::string> ciphertexts = saltedEncryptor->encryptWithSalt(plaintexts);
            encryptedUser = ciphertexts[0];
            encryptedPass = ciphertexts[1];
        } else {
            encryptedUser = credEncryptor->encrypt(user);
            encryptedPass = credEncryptor->encrypt(pass);
        }

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

std::optional<DecryptedCredential> CredentialsManager::getCredentials(const std::string& platform) {
    try {
        if (platform.empty()) {
            std::cerr << "Error: Empty platform name provided\n";
            return std::nullopt;
        }

        auto credentialDataOpt = storage->getCredentials(platform);
        if (!credentialDataOpt) {
            // This is not an error, just means no credentials for this platform
            return std::nullopt;
        }

        CredentialData credentialData = *credentialDataOpt;
        DecryptedCredential decryptedCredential;

        // Create a temporary encryptor for the specific type
        auto encryptor = EncryptionFactory::createForMasterPassword(
            credentialData.encryption_type, 
            currentMasterPassword,
            ConfigManager::getInstance().getLfsrTaps(),
            ConfigManager::getInstance().getLfsrInitState()
        );

        if (auto saltedDecryptor = dynamic_cast<ISaltedEncryption*>(encryptor.get())) {
            std::vector<std::string> encrypted_data = {credentialData.encrypted_user, credentialData.encrypted_pass};
            std::vector<std::string> decrypted_data = saltedDecryptor->decryptWithSalt(encrypted_data);
            if (decrypted_data.size() == 2) {
                decryptedCredential.username = decrypted_data[0];
                decryptedCredential.password = decrypted_data[1];
            } else {
                return std::nullopt;
            }
        } else {
            decryptedCredential.username = encryptor->decrypt(credentialData.encrypted_user);
            decryptedCredential.password = encryptor->decrypt(credentialData.encrypted_pass);
        }

        return decryptedCredential;
    } catch (const std::exception& e) {
        std::cerr << "Exception while getting credentials: " << e.what() << std::endl;
        return std::nullopt;
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
