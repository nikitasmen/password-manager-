#include "MigrationHelper.h"
#include "../crypto/lfsr_encryption.h"
#include "../core/api.h"
#include "../crypto/encryption_factory.h"
#include <openssl/rand.h>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <fstream>

MigrationHelper& MigrationHelper::getInstance() {
    static MigrationHelper instance;
    return instance;
}

namespace {
    // Private helper to handle moving the data file if the path changes
    bool handleDataPathChange(const std::string& oldPath, const std::string& newPath) {
        if (oldPath == newPath) {
            return true; // No change needed
        }

        std::cout << "Data path changed, moving data file..." << std::endl;
        std::ifstream oldFile(oldPath);
        if (!oldFile.good()) {
            std::cout << "No existing data file to move." << std::endl;
            return true; // Not an error if the old file doesn't exist
        }

        // Ensure the destination directory exists (requires C++17 filesystem)
        size_t lastSlash = newPath.find_last_of("/\\");
        if (lastSlash != std::string::npos) {
            std::filesystem::create_directories(newPath.substr(0, lastSlash));
        }

        std::ifstream src(oldPath, std::ios::binary);
        std::ofstream dst(newPath, std::ios::binary);

        if (!src || !dst) {
            std::cerr << "Failed to move data file from '" << oldPath << "' to '" << newPath << "'" << std::endl;
            return false;
        }

        dst << src.rdbuf();
        src.close();
        dst.close();
        std::cout << "Data file successfully copied to new location." << std::endl;
        // std::remove(oldPath.c_str()); // Optional: remove old file
        return true;
    }

    // Private helper to handle all encryption-related migrations
    bool handleEncryptionSettingsChange(const AppConfig& oldConfig, const AppConfig& newConfig, const std::string& masterPassword, const std::string& dataPath) {
        const auto oldEnc = oldConfig.defaultEncryption;
        const auto newEnc = newConfig.defaultEncryption;
        const auto& oldTaps = oldConfig.lfsrTaps;
        const auto& oldInit = oldConfig.lfsrInitState;
        const auto& newTaps = newConfig.lfsrTaps;
        const auto& newInit = newConfig.lfsrInitState;

        bool lfsrParamsChanged = (oldTaps != newTaps) || (oldInit != newInit);

        if (oldEnc == newEnc && !lfsrParamsChanged) {
            return true; // No encryption changes
        }

        // If encryption type changes, master password must be migrated
        if (oldEnc != newEnc) {
            std::cout << "Encryption type changed, migrating master password..." << std::endl;
            if (!MigrationHelper::getInstance().migrateMasterPasswordForEncryptionChange(oldEnc, newEnc, oldTaps, oldInit, newTaps, newInit, masterPassword, dataPath)) {
                std::cerr << "Failed to migrate master password for encryption type change!" << std::endl;
                return false;
            }
            std::cout << "Master password encryption migration completed." << std::endl;
        }

        // If LFSR settings change, all LFSR credentials must be migrated
        if (lfsrParamsChanged) {
            std::cout << "LFSR settings changed, migrating credentials..." << std::endl;
            if (!MigrationHelper::getInstance().migrateCredentialsForLfsrChange(oldTaps, oldInit, newTaps, newInit, masterPassword, dataPath)) {
                std::cerr << "Failed to migrate LFSR credentials for new taps/init state!" << std::endl;
                return false;
            }
            std::cout << "LFSR credentials migration completed." << std::endl;
        }

        return true;
    }
} // namespace

// Generate a random salt for LFSR encryption
std::string MigrationHelper::generateRandomSalt() {
    const std::string charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charset.size() - 1);
    
    std::string salt;
    for (int i = 0; i < 16; ++i) {
        salt += charset[dis(gen)];
    }
    return salt;
}

bool MigrationHelper::migrateCredentialsForLfsrChange(
    const std::vector<int>& oldTaps,
    const std::vector<int>& oldInitState,
    const std::vector<int>& newTaps,
    const std::vector<int>& newInitState,
    const std::string& masterPassword,
    const std::string& dataPath) {
    
    if (masterPassword.empty()) {
        std::cerr << "Error: Master password is required for LFSR migration" << std::endl;
        return false;
    }
    
    try {
        // Create storage instance
        std::unique_ptr<JsonStorage> storage = std::make_unique<JsonStorage>(dataPath);
        
        // Get all platforms
        std::vector<std::string> platforms = storage->getAllPlatforms();
        
        if (platforms.empty()) {
            std::cout << "No credentials to migrate" << std::endl;
            
            // Still need to update master password
            return updateMasterPasswordWithNewLfsr(
                oldTaps, oldInitState, newTaps, newInitState, masterPassword, dataPath);
        }
        
        int successCount = 0;
        int totalCount = platforms.size();
        
        std::cout << "Starting migration of " << totalCount << " platforms..." << std::endl;
        
        // Process each platform's credentials
        for (const auto& platform : platforms) {
            auto credDataOpt = storage->getCredentials(platform);
            
            if (credDataOpt) {
                CredentialData& credentials = *credDataOpt;
                
                // Only process LFSR encrypted credentials
                if (credentials.encryption_type == EncryptionType::LFSR) {
                    // Pure LFSR encryption
                    std::unique_ptr<Encryption> oldEncryptor = 
                        std::make_unique<Encryption>(EncryptionType::LFSR, oldTaps, oldInitState, masterPassword);
                    std::unique_ptr<Encryption> newEncryptor = 
                        std::make_unique<Encryption>(EncryptionType::LFSR, newTaps, newInitState, masterPassword);

                    if (reencryptCredential(platform, credentials, oldEncryptor.get(), newEncryptor.get(), storage.get())) {
                        successCount++;
                        std::cout << "Migrated LFSR credentials for: " << platform << std::endl;
                    } else {
                        std::cerr << "Failed to migrate LFSR credentials for: " << platform << std::endl;
                    }
                } else {
                    // Skip credentials with non-LFSR encryption, but count as success
                    successCount++;
                    std::cout << "Skipped non-LFSR credentials for: " << platform << " (no migration needed)" << std::endl;
                }
            } else {
                std::cerr << "Could not retrieve credentials for platform: " << platform << std::endl;
            }
        }
        
        std::cout << "Migration complete: " << successCount << "/" << totalCount << " credentials updated" << std::endl;
        
        // Now update the master password with new LFSR settings
        bool masterPasswordUpdated = updateMasterPasswordWithNewLfsr(
            oldTaps, oldInitState, newTaps, newInitState, masterPassword, dataPath);
            
        if (!masterPasswordUpdated) {
            std::cerr << "Warning: Master password could not be updated with new LFSR settings" << std::endl;
        }
        
        // Return true if all credentials were updated and master password was updated
        return (successCount == totalCount && masterPasswordUpdated);
        
    } catch (const std::exception& e) {
        std::cerr << "Error during LFSR migration: " << e.what() << std::endl;
        return false;
    }
}

bool MigrationHelper::updateMasterPasswordWithNewLfsr(
    const std::vector<int>& oldTaps,
    const std::vector<int>& oldInitState,
    const std::vector<int>& newTaps,
    const std::vector<int>& newInitState,
    const std::string& masterPassword,
    const std::string& dataPath) {

    // Delegate to the more generic master password migration function.
    // This handles the case of an LFSR -> LFSR parameter change.
    return migrateMasterPasswordForEncryptionChange(
        EncryptionType::LFSR, 
        EncryptionType::LFSR, 
        oldTaps, 
        oldInitState, 
        newTaps, 
        newInitState, 
        masterPassword, 
        dataPath
    );
    return true;
}

bool MigrationHelper::reencryptCredential(
    const std::string& platform,
    const CredentialData& credentials,
    Encryption* oldEncryptor,
    Encryption* newEncryptor,
    JsonStorage* storage) {
    
    try {
        std::string encryptedUser = credentials.encrypted_user;
        std::string encryptedPass = credentials.encrypted_pass;
        
        // Decrypt with correct method based on algorithm
        std::string username, password;
        if (oldEncryptor->getAlgorithm() == EncryptionType::LFSR) {
            username = oldEncryptor->decryptWithSalt(encryptedUser);
            password = oldEncryptor->decryptWithSalt(encryptedPass);
        } else {
            std::cerr << "Unknown encryption algorithm for platform: " << platform << std::endl;
            return false;
        }
        
        // Re-encrypt with new LFSR settings
        std::string newEncryptedUser, newEncryptedPass;
        try {
            // Use the same encryption method as the old encryptor for consistency
            if (oldEncryptor->getAlgorithm() == EncryptionType::LFSR) {
                // For LFSR, use salt-based encryption
                newEncryptedUser = newEncryptor->encryptWithSalt(username);
                newEncryptedPass = newEncryptor->encryptWithSalt(password);
            } else {
                std::cerr << "Unknown encryption algorithm for platform: " << platform << std::endl;
                return false;
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to re-encrypt credentials for " << platform << ": " << e.what() << std::endl;
            return false;
        }
        
        // Save back with the same encryption type
        int encType = static_cast<int>(credentials.encryption_type);
        
        // Delete existing credentials and add new ones
        if (!storage->deleteCredentials(platform)) {
            std::cerr << "Failed to delete old credentials for " << platform << std::endl;
            return false;
        }
        
        if (!storage->addCredentials(platform, newEncryptedUser, newEncryptedPass, encType)) {
            std::cerr << "Failed to save re-encrypted credentials for " << platform << std::endl;
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error re-encrypting credential for " << platform << ": " << e.what() << std::endl;
        return false;
    }
}

bool MigrationHelper::migrateMasterPasswordForEncryptionChange(
    EncryptionType oldType,
    EncryptionType newType,
    const std::vector<int>& oldTaps,
    const std::vector<int>& oldInitState,
    const std::vector<int>& newTaps,
    const std::vector<int>& newInitState,
    const std::string& masterPassword,
    const std::string& dataPath) {

    auto storage = std::make_unique<JsonStorage>(dataPath);
    std::string currentEncrypted = storage->getMasterPassword();

    if (currentEncrypted.empty()) {
        std::cerr << "Error: No master password found to migrate." << std::endl;
        return false;
    }

    std::string oldTypeStr = (oldType == EncryptionType::AES) ? "AES" : "LFSR";
    std::string newTypeStr = (newType == EncryptionType::AES) ? "AES" : "LFSR";

    std::cout << "Starting master password migration from " << oldTypeStr 
              << " to " << newTypeStr << "..." << std::endl;

    // 1. Verify the current master password is correct by decrypting the verification token
    // The stored value is in format: salt$encrypted_verification_token
    size_t delimiter = currentEncrypted.find('$');
    if (delimiter == std::string::npos) {
        std::cerr << "Invalid format for stored master password" << std::endl;
        return false;
    }
    
    std::string salt = currentEncrypted.substr(0, delimiter);
    std::string encryptedToken = currentEncrypted.substr(delimiter + 1);
    
    // Create decryptor with the old encryption type and salt
    std::unique_ptr<IEncryption> oldEncryptor;
    if (oldType == EncryptionType::LFSR) {
        // For LFSR, create with the existing salt
        oldEncryptor = std::make_unique<LFSREncryption>(oldTaps, oldInitState, salt);
    } else {
        // For AES and others, use the factory
        EncryptionConfigParameters oldParams;
        oldParams.type = oldType;
        oldParams.masterPassword = masterPassword;
        oldParams.lfsrTaps = oldTaps;
        oldParams.lfsrInitState = oldInitState;
        oldEncryptor = EncryptionFactory::create(oldParams);  
    }
    
    if (!oldEncryptor) {
        std::cerr << "Failed to create decryptor for old encryption type" << std::endl;
        return false;
    }
    
    oldEncryptor->setMasterPassword(masterPassword);
    
    // Try to decrypt the verification token
    std::string decryptedToken;
    try {
        std::cout << "Attempting decryption with " << oldTypeStr << "..." << std::endl;
        decryptedToken = oldEncryptor->decrypt(encryptedToken);
        
        // Verify it's a valid verification token
        if (decryptedToken.empty() || decryptedToken.find("verify_") != 0) {
            std::cerr << "Decryption with " << oldTypeStr << " failed: Invalid verification token" << std::endl;
            return false;
        }
        
        std::cout << "Successfully verified master password with " << oldTypeStr << "." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Decryption with " << oldTypeStr << " failed: " << e.what() << std::endl;
        return false;
    }

    // 2. Create the new encryptor for the new encryption type
    std::unique_ptr<IEncryption> newEncryptor;
    std::string newSalt;
    
    if (newType == EncryptionType::LFSR) {
        // For LFSR, generate a new salt
        unsigned char saltBytes[16];
        if (RAND_bytes(saltBytes, sizeof(saltBytes)) != 1) {
            std::cerr << "Failed to generate random salt for new LFSR encryption" << std::endl;
            return false;
        }
        newSalt = std::string(reinterpret_cast<const char*>(saltBytes), sizeof(saltBytes));
        newEncryptor = std::make_unique<LFSREncryption>(newTaps, newInitState, newSalt);
    } else { // For AES and others
        // Generate a new salt for AES encryption for better security
        unsigned char saltBytes[16];
        if (RAND_bytes(saltBytes, sizeof(saltBytes)) != 1) {
            std::cerr << "Failed to generate random salt for new AES encryption" << std::endl;
            return false;
        }
        newSalt = std::string(reinterpret_cast<const char*>(saltBytes), sizeof(saltBytes));

        // For AES and others, use the factory. The salt is not passed directly but will be used to store the final value.
        EncryptionConfigParameters newParams;
        newParams.type = newType;
        newParams.masterPassword = masterPassword;
        newParams.lfsrTaps = newTaps;
        newParams.lfsrInitState = newInitState;
        newEncryptor = EncryptionFactory::create(newParams);  
    }
    
    if (!newEncryptor) {
        std::cerr << "Failed to create encryptor for new encryption type" << std::endl;
        return false;
    }
    
    newEncryptor->setMasterPassword(masterPassword);

    // 3. Encrypt the verification token with the new encryption type
    std::string newEncryptedToken;
    try {
        std::cout << "Encrypting verification token with new type: " << newTypeStr << "..." << std::endl;
        newEncryptedToken = newEncryptor->encrypt(decryptedToken);
    } catch (const std::exception& e) {
        std::cerr << "Failed to encrypt verification token: " << e.what() << std::endl;
        return false;
    }

    // 4. Update the stored password with new salt and encrypted token
    std::string newStoredFormat = newSalt + "$" + newEncryptedToken;
    if (!storage->updateMasterPassword(newStoredFormat)) {
        std::cerr << "Failed to update master password in storage." << std::endl;
        return false;
    }
    
    std::cout << "Successfully migrated master password from " << oldTypeStr 
              << " to " << newTypeStr << " encryption." << std::endl;
    return true;
}

bool MigrationHelper::applySettingsFromConfig(const AppConfig& oldConfig, const AppConfig& newConfig, const std::string& masterPassword) {
    if (masterPassword.empty()) {
        std::cerr << "Error: Master password is required for migration but was not provided." << std::endl;
        return false;
    }

    // Verify master password before proceeding
    CredentialsManager verifier(oldConfig.dataPath);
    if (!verifier.login(masterPassword)) {
        std::cerr << "Error: Incorrect master password provided. Settings will not be applied." << std::endl;
        return false;
    }

    std::cout << "Starting settings migration..." << std::endl;

    bool success = true;
    ConfigManager& configMgr = ConfigManager::getInstance();
    
    try {
        // 1. Handle data path change
        if (!handleDataPathChange(oldConfig.dataPath, newConfig.dataPath)) {
            success = false;
        }

        // 2. Handle all encryption-related changes
        if (success && !handleEncryptionSettingsChange(oldConfig, newConfig, masterPassword, newConfig.dataPath)) {
            success = false;
        }

        // 3. Update and save the configuration if all migrations were successful
        if (success) {
            try {
                configMgr.updateConfig(newConfig);
                std::cout << "Configuration updated successfully." << std::endl;
                if (!configMgr.saveConfig()) {
                    std::cerr << "Warning: Failed to save configuration to file." << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "Failed to update configuration: " << e.what() << std::endl;
                success = false;
            }
        }

        if (success) {
            std::cout << "All settings applied and migrations completed successfully!" << std::endl;
        } else {
            std::cerr << "Settings migration completed with errors. Some changes may not have been applied." << std::endl;
        }
        
        return success;
        
    } catch (const std::exception& e) {
        std::cerr << "Unexpected error during settings migration: " << e.what() << std::endl;
        return false;
    } catch (...) {
        std::cerr << "Unknown error during settings migration." << std::endl;
        return false;
    }
}