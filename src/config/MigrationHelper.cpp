#include "MigrationHelper.h"
#include <iostream>
#include <memory>
#include <random>
#include <sstream>

MigrationHelper& MigrationHelper::getInstance() {
    static MigrationHelper instance;
    return instance;
}

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

    std::unique_ptr<JsonStorage> storage = std::make_unique<JsonStorage>(dataPath);
    std::string storedPassword = storage->getMasterPassword();
    if (storedPassword.empty()) {
        std::cout << "No master password to migrate" << std::endl;
        return true;
    }

    EncryptionType defaultEnc = ConfigManager::getInstance().getDefaultEncryption();
    if (defaultEnc == EncryptionType::AES) {
        std::cout << "Skipping master password migration (config is AES or stored password is AES-encrypted)." << std::endl;
        return true;
    }

    std::string decryptedPassword;
    try {
        decryptedPassword = Encryption::decryptMasterPassword(defaultEnc, oldTaps, oldInitState, storedPassword, masterPassword);
    } catch (const std::exception& e) {
        std::cerr << "Failed to decrypt master password: " << e.what() << std::endl;
        return false;
    }

    if (decryptedPassword != masterPassword) {
        std::cerr << "Failed to migrate master password - could not decrypt with old settings" << std::endl;
        return false;
    }

    std::string newEncryptedPassword;
    try {
        newEncryptedPassword = Encryption::encryptMasterPassword(defaultEnc, newTaps, newInitState, masterPassword);
    } catch (const std::exception& e) {
        std::cerr << "Failed to encrypt master password: " << e.what() << std::endl;
        return false;
    }

    if (!storage->updateMasterPassword(newEncryptedPassword)) {
        std::cerr << "Failed to update master password with new encryption" << std::endl;
        return false;
    }
    std::cout << "Master password successfully migrated with LFSR encryption" << std::endl;
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

    // Get encryption type names from config
    std::string oldTypeStr = "Unknown";
    std::string newTypeStr = "Unknown";
    
    switch (oldType) {
        case EncryptionType::AES: oldTypeStr = "AES"; break;
        case EncryptionType::LFSR: oldTypeStr = "LFSR"; break;
        default: oldTypeStr = "Unknown"; break;
    }
    
    switch (newType) {
        case EncryptionType::AES: newTypeStr = "AES"; break;
        case EncryptionType::LFSR: newTypeStr = "LFSR"; break;
        default: newTypeStr = "Unknown"; break;
    }
    
    std::cout << "Starting master password migration from " << 
        oldTypeStr << " to " << newTypeStr << std::endl;

    std::unique_ptr<JsonStorage> storage = std::make_unique<JsonStorage>(dataPath);
    std::string storedPassword = storage->getMasterPassword();
    
    if (storedPassword.empty()) {
        std::cout << "No master password to migrate" << std::endl;
        return true;
    }

    // 1. First check if the stored password is already in the new format
    if (newType == EncryptionType::LFSR) {
        // For LFSR, we'll just store the password directly since we can't decrypt the old one
        std::cout << "Migrating to LFSR - will store new encrypted password" << std::endl;
    } else {
        // For other encryption types, try to decrypt with the new type first
        try {
            std::cout << "Attempting to verify current master password..." << std::endl;
            std::string decrypted = Encryption::decryptMasterPassword(
                newType, newTaps, newInitState, storedPassword, masterPassword);
            if (decrypted == masterPassword) {
                std::cout << "Master password is already using the new encryption type" << std::endl;
                return true;  // Already migrated
            }
        } catch (const std::exception& e) {
            std::cout << "Master password not yet migrated to new encryption type, proceeding with migration..." << std::endl;
        }
    }

    // 2. For migration to LFSR, we'll use the master password directly
    //    since we can't reliably decrypt the old password
    std::string decryptedPassword = masterPassword;
    std::cout << "Using provided master password for migration to LFSR" << std::endl;

    // 3. Ensure we have a valid password
    if (decryptedPassword.empty()) {
        std::cerr << "Error: Cannot use empty password for migration" << std::endl;
        return false;
    }

    // 4. Create encryptors for both old and new types
    std::unique_ptr<Encryption> oldEncryptor = std::make_unique<Encryption>(oldType, oldTaps, oldInitState, masterPassword);
    std::unique_ptr<Encryption> newEncryptor = std::make_unique<Encryption>(newType, newTaps, newInitState, masterPassword);

    // 5. Encrypt with the new encryption type
    std::string newEncrypted;
    try {
        std::cout << "Encrypting master password with new encryption type..." << std::endl;
        
        if (newType == EncryptionType::LFSR) {
            // For LFSR, generate a random salt
            std::string salt = generateRandomSalt();
            
            // Create a new encryptor with the new LFSR settings and salted password
            std::string saltedPassword = masterPassword + salt;
            auto saltedEncryptor = std::make_unique<Encryption>(
                newType, 
                newTaps, 
                newInitState, 
                saltedPassword
            );
            
            // Encrypt the master password with the salted key
            std::string encrypted = saltedEncryptor->encrypt(masterPassword);
            
            // Store as "salt:encrypted_data"
            newEncrypted = salt + ":" + encrypted;
        } else {
            // For non-LFSR (AES), use regular encryption
            newEncrypted = newEncryptor->encrypt(decryptedPassword);
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to encrypt master password with new encryption type: " << e.what() << std::endl;
        return false;
    }

    // 6. Update the stored password
    if (!storage->updateMasterPassword(newEncrypted)) {
        std::cerr << "Failed to update master password with new encryption." << std::endl;
        return false;
    }
    
    // 7. Verify the new encryption works
    try {
        std::string verify;
        if (newType == EncryptionType::LFSR) {
            // For LFSR, extract salt and encrypted data
            size_t saltEnd = newEncrypted.find(':');
            if (saltEnd != std::string::npos) {
                std::string salt = newEncrypted.substr(0, saltEnd);
                std::string encrypted = newEncrypted.substr(saltEnd + 1);
                
                // Create a decryptor with the salted password
                std::string saltedPassword = masterPassword + salt;
                auto saltedDecryptor = std::make_unique<Encryption>(
                    newType,
                    newTaps,
                    newInitState,
                    saltedPassword
                );
                
                // Decrypt with the salted key
                verify = saltedDecryptor->decrypt(encrypted);
            } else {
                // Fallback to non-salted decryption if format is unexpected
                std::cerr << "Warning: No salt found in encrypted data, using non-salted decryption" << std::endl;
                auto verifyEncryptor = std::make_unique<Encryption>(
                    newType,
                    newTaps,
                    newInitState,
                    masterPassword
                );
                verify = verifyEncryptor->decrypt(newEncrypted);
            }
        } else {
            // For non-LFSR, use regular decryption
            verify = newEncryptor->decrypt(newEncrypted);
        }
        
        if (verify != masterPassword) {
            std::cerr << "Verification of newly encrypted password failed" << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to verify newly encrypted password: " << e.what() << std::endl;
        return false;
    }

    std::cout << "Successfully migrated master password from " << 
        oldTypeStr << " to " << newTypeStr << " encryption." << std::endl;
    return true;
}