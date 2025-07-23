#include "MigrationHelper.h"
#include <iostream>
#include <memory>

namespace {
    std::string decryptMasterPassword(
        EncryptionType type,
        const std::vector<int>& taps,
        const std::vector<int>& initState,
        const std::string& encrypted,
        const std::string& masterPassword
    ) {
        std::unique_ptr<Encryption> enc = std::make_unique<Encryption>(type, taps, initState, masterPassword);
        if (type == EncryptionType::LFSR) {
            try {
                return enc->decryptWithSalt(encrypted);
            } catch (...) {
                return enc->decrypt(encrypted);
            }
        } else if (type == EncryptionType::AES) {
            return enc->decrypt(encrypted);
        }
        throw std::runtime_error("Unknown encryption type for master password decryption");
    }

    std::string encryptMasterPassword(
        EncryptionType type,
        const std::vector<int>& taps,
        const std::vector<int>& initState,
        const std::string& masterPassword
    ) {
        std::unique_ptr<Encryption> enc = std::make_unique<Encryption>(type, taps, initState, masterPassword);
        if (type == EncryptionType::LFSR) {
            return enc->encryptWithSalt(masterPassword);
        } else if (type == EncryptionType::AES) {
            return enc->encrypt(masterPassword);
        }
        throw std::runtime_error("Unknown encryption type for master password encryption");
    }
}

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
            
            // Only re-encrypt credentials that use LFSR
            if (credentials.size() >= 3) {
                // Check encryption type (if specified)
                int encType = static_cast<int>(EncryptionType::LFSR); // Default to LFSR
                try {
                    encType = std::stoi(credentials[2]);
                } catch (...) {
                    // If not a valid number, assume LFSR
                }
                
                // Only process LFSR encrypted credentials
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
                } else {
                    // Skip credentials with non-LFSR encryption, but count as success
                    successCount++;
                    std::cout << "Skipped non-LFSR credentials for: " << platform << " (no migration needed)" << std::endl;
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
        decryptedPassword = decryptMasterPassword(defaultEnc, oldTaps, oldInitState, storedPassword, masterPassword);
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
        newEncryptedPassword = encryptMasterPassword(defaultEnc, newTaps, newInitState, masterPassword);
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
        
        // Decrypt with correct method based on algorithm
        std::string username, password;
        if (oldEncryptor->getAlgorithm() == EncryptionType::LFSR) {
            try {
                username = oldEncryptor->decryptWithSalt(encryptedUser);
                password = oldEncryptor->decryptWithSalt(encryptedPass);
            } catch (const std::exception&) {
                try {
                    username = oldEncryptor->decrypt(encryptedUser);
                    password = oldEncryptor->decrypt(encryptedPass);
                } catch (const std::exception& e) {
                    std::cerr << "Failed to decrypt credentials for " << platform << ": " << e.what() << std::endl;
                    return false;
                }
            }
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
        int encType = static_cast<int>(ConfigManager::getInstance().getDefaultEncryption());
        if (credentials.size() >= 3) {
            try {
                encType = std::stoi(credentials[2]);
            } catch (...) {
                // If not valid, keep default encryption
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

bool MigrationHelper::migrateMasterPasswordForEncryptionChange(
    EncryptionType oldType,
    EncryptionType newType,
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

    std::string decryptedPassword;
    try {
        decryptedPassword = decryptMasterPassword(oldType, oldTaps, oldInitState, storedPassword, masterPassword);
    } catch (const std::exception& e) {
        std::cerr << "Failed to decrypt master password: " << e.what() << std::endl;
        return false;
    }

    if (decryptedPassword != masterPassword) {
        std::cerr << "Master password verification failed during migration." << std::endl;
        return false;
    }

    std::string newEncrypted;
    try {
        newEncrypted = encryptMasterPassword(newType, newTaps, newInitState, masterPassword);
    } catch (const std::exception& e) {
        std::cerr << "Failed to encrypt master password: " << e.what() << std::endl;
        return false;
    }

    if (!storage->updateMasterPassword(newEncrypted)) {
        std::cerr << "Failed to update master password with new encryption." << std::endl;
        return false;
    }
    std::cout << "Master password migrated to new encryption type successfully." << std::endl;
    return true;
}