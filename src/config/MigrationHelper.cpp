#include "MigrationHelper.h"
#include <iostream>
#include <memory>

MigrationHelper& MigrationHelper::getInstance() {
    static MigrationHelper instance;
    return instance;
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
            std::vector<std::string> credentials = storage->getCredentials(platform);
            
            // Only re-encrypt credentials that use LFSR or AES_LFSR
            if (credentials.size() >= 3) {
                // Check encryption type (if specified)
                int encType = 0; // Default to LFSR
                try {
                    encType = std::stoi(credentials[2]);
                } catch (...) {
                    // If not a valid number, assume LFSR
                }
                
                // Process both LFSR and AES_LFSR encrypted credentials
                if (encType == static_cast<int>(EncryptionType::LFSR)) {
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
                } else if (encType == static_cast<int>(EncryptionType::AES_LFSR)) {
                    // AES_LFSR hybrid encryption also needs to be updated since it uses LFSR components
                    std::unique_ptr<Encryption> oldAesLfsrEncryptor = 
                        std::make_unique<Encryption>(EncryptionType::AES_LFSR, oldTaps, oldInitState, masterPassword);
                        
                    std::unique_ptr<Encryption> newAesLfsrEncryptor = 
                        std::make_unique<Encryption>(EncryptionType::AES_LFSR, newTaps, newInitState, masterPassword);
                        
                    if (reencryptCredential(platform, credentials, oldAesLfsrEncryptor.get(), newAesLfsrEncryptor.get(), storage.get())) {
                        successCount++;
                        std::cout << "Migrated AES_LFSR credentials for: " << platform << std::endl;
                    } else {
                        std::cerr << "Failed to migrate AES_LFSR credentials for: " << platform << std::endl;
                    }
                } else {
                    // Skip credentials with pure AES encryption, but count as success
                    successCount++;
                    std::cout << "Skipped AES-only credentials for: " << platform << " (no migration needed)" << std::endl;
                }
            } else {
                std::cerr << "Invalid credential format for platform: " << platform << std::endl;
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
    
    try {
        // Create storage instance
        std::unique_ptr<JsonStorage> storage = std::make_unique<JsonStorage>(dataPath);
        
        // Check if master password exists
        std::string storedPassword = storage->getMasterPassword();
        if (storedPassword.empty()) {
            std::cout << "No master password to migrate" << std::endl;
            return true;
        }
        
        std::cout << "Migrating master password..." << std::endl;
        
        // Try to decrypt and re-encrypt master password with different encryption types
        bool successfulMigration = false;
        
        // First, try with LFSR encryption
        try {
            std::unique_ptr<Encryption> oldLfsrEncryptor = 
                std::make_unique<Encryption>(EncryptionType::LFSR, oldTaps, oldInitState, masterPassword);
            
            std::unique_ptr<Encryption> newLfsrEncryptor = 
                std::make_unique<Encryption>(EncryptionType::LFSR, newTaps, newInitState, masterPassword);
            
            // Try to decrypt with old settings
            std::string decryptedPassword;
            try {
                // Try with salt first
                decryptedPassword = oldLfsrEncryptor->decryptWithSalt(storedPassword);
            } catch (const std::exception&) {
                // Fallback to regular decryption
                decryptedPassword = oldLfsrEncryptor->decrypt(storedPassword);
            }
            
            // Verify the decrypted password matches
            if (decryptedPassword == masterPassword) {
                // Re-encrypt with new settings using salt for LFSR
                std::string newEncryptedPassword = newLfsrEncryptor->encryptWithSalt(masterPassword);
                
                // Update the stored password
                if (storage->updateMasterPassword(newEncryptedPassword)) {
                    std::cout << "Master password successfully migrated with LFSR encryption" << std::endl;
                    successfulMigration = true;
                }
            }
        } catch (const std::exception&) {
            // LFSR migration failed, continue to AES_LFSR
        }
        
        // If LFSR migration failed, try AES_LFSR
        if (!successfulMigration) {
            try {
                std::unique_ptr<Encryption> oldAesLfsrEncryptor = 
                    std::make_unique<Encryption>(EncryptionType::AES_LFSR, oldTaps, oldInitState, masterPassword);
                
                std::unique_ptr<Encryption> newAesLfsrEncryptor = 
                    std::make_unique<Encryption>(EncryptionType::AES_LFSR, newTaps, newInitState, masterPassword);
                
                // Try to decrypt with old settings
                std::string decryptedPassword = oldAesLfsrEncryptor->decrypt(storedPassword);
                
                // Verify the decrypted password matches
                if (decryptedPassword == masterPassword) {
                    // Re-encrypt with new settings (no salt for AES_LFSR)
                    std::string newEncryptedPassword = newAesLfsrEncryptor->encrypt(masterPassword);
                    
                    // Update the stored password
                    if (storage->updateMasterPassword(newEncryptedPassword)) {
                        std::cout << "Master password successfully migrated with AES_LFSR encryption" << std::endl;
                        successfulMigration = true;
                    }
                }
            } catch (const std::exception&) {
                // AES_LFSR migration also failed
            }
        }
        
        if (!successfulMigration) {
            std::cerr << "Failed to migrate master password - could not decrypt with old settings" << std::endl;
            return false;
        }
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error during master password migration: " << e.what() << std::endl;
        return false;
    }
}

bool MigrationHelper::reencryptCredential(
    const std::string& platform,
    const std::vector<std::string>& credentials,
    Encryption* oldEncryptor,
    Encryption* newEncryptor,
    JsonStorage* storage) {
    
    try {
        if (credentials.size() < 2) {
            std::cerr << "Invalid credential format for platform: " << platform << std::endl;
            return false;
        }
        
        // Get encrypted username and password
        std::string encryptedUser = credentials[0];
        std::string encryptedPass = credentials[1];
        
        // Decrypt with old LFSR settings
        std::string username, password;
        try {
            // Try with salt decryption first
            username = oldEncryptor->decryptWithSalt(encryptedUser);
            password = oldEncryptor->decryptWithSalt(encryptedPass);
        } catch (const std::exception&) {
            try {
                // Fallback to legacy decryption if salt decryption fails
                username = oldEncryptor->decrypt(encryptedUser);
                password = oldEncryptor->decrypt(encryptedPass);
            } catch (const std::exception& e) {
                std::cerr << "Failed to decrypt credentials for " << platform << ": " << e.what() << std::endl;
                return false;
            }
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
                // For AES_LFSR, use regular encryption (AES part handles its own salting)
                newEncryptedUser = newEncryptor->encrypt(username);
                newEncryptedPass = newEncryptor->encrypt(password);
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to re-encrypt credentials for " << platform << ": " << e.what() << std::endl;
            return false;
        }
        
        // Save back with the same encryption type
        int encType = static_cast<int>(EncryptionType::LFSR);
        if (credentials.size() >= 3) {
            try {
                encType = std::stoi(credentials[2]);
            } catch (...) {
                // If not valid, keep LFSR
            }
        }
        
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
