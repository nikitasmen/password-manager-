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
#include "../crypto/rsa_encryption.h"

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
    
    EncryptionConfigParameters params;
    params.type = type;
    params.masterPassword = password;
    params.lfsrTaps = lfsrTaps;
    params.lfsrInitState = lfsrInitState;
    encryptor = EncryptionFactory::create(params);
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
            EncryptionConfigParameters params;
            params.type = masterEncType;
            params.masterPassword = password;
            params.lfsrTaps = configTaps;
            params.lfsrInitState = configInitState;
            tempEncryptor = EncryptionFactory::create(params);
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
            EncryptionConfigParameters params;
            params.type = masterEncType;
            params.masterPassword = newPassword;
            params.lfsrTaps = configTaps;
            params.lfsrInitState = configInitState;
            masterEncryptor = EncryptionFactory::create(params);
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
    try {
        // Enhanced input validation
        if (platform.empty()) {
            std::cerr << "Error: Platform name cannot be empty\n";
            return false;
        }
        if (user.empty()) {
            std::cerr << "Error: Username cannot be empty\n";
            return false;
        }
        if (pass.empty()) {
            std::cerr << "Error: Password cannot be empty\n";
            return false;
        }
        
        // Check if user is logged in
        if (currentMasterPassword.empty()) {
            std::cerr << "Error: Must be logged in to add credentials\n";
            return false;
        }
    
        // Use provided encryption type or default to instance type
        EncryptionType credEncType = encryptionType.value_or(this->encryptionType);
    
        EncryptionConfigParameters params;
        params.type = credEncType;
        params.masterPassword = currentMasterPassword;
        params.lfsrTaps = ConfigManager::getInstance().getLfsrTaps();
        params.lfsrInitState = ConfigManager::getInstance().getLfsrInitState();
        auto credEncryptor = EncryptionFactory::create(params);

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

        CredentialData credData;
        credData.encryption_type = credEncType;

        if (credEncType == EncryptionType::RSA) {
            auto rsaEncryptor = dynamic_cast<RSAEncryption*>(credEncryptor.get());
            if (!rsaEncryptor) {
                throw std::runtime_error("Failed to cast to RSAEncryption for key retrieval.");
            }
            credData.rsa_public_key = rsaEncryptor->getPublicKey();
            credData.rsa_private_key = rsaEncryptor->getEncryptedPrivateKeyData();
        }

        credData.encrypted_user = encryptedUser;
        credData.encrypted_pass = encryptedPass;

        // Store the credentials with encryption type
        storage->addCredentials(platform, credData);

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

        std::unique_ptr<IEncryption> encryptor;
        if (credentialData.encryption_type == EncryptionType::RSA) {
            if (!credentialData.rsa_public_key.has_value() || !credentialData.rsa_private_key.has_value()) {
                throw std::runtime_error("RSA keys not found for RSA-encrypted credential.");
            }
            EncryptionConfigParameters params;
            params.type = credentialData.encryption_type;
            params.publicKey = credentialData.rsa_public_key.value();
            params.privateKey = credentialData.rsa_private_key.value();
            params.masterPassword = currentMasterPassword;
            encryptor = EncryptionFactory::create(params);

        } else {
            // Create a temporary encryptor for the specific type
            EncryptionConfigParameters params;
            params.type = credentialData.encryption_type;
            params.masterPassword = currentMasterPassword;
            params.lfsrTaps = ConfigManager::getInstance().getLfsrTaps();
            params.lfsrInitState = ConfigManager::getInstance().getLfsrInitState();
            encryptor = EncryptionFactory::create(params);
        }

        if (!encryptor) {
            throw std::runtime_error("Failed to create decryptor for credential.");
        }

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
