#ifndef MIGRATION_HELPER_H
#define MIGRATION_HELPER_H

#include <string>
#include <vector>
#include <memory>
#include "GlobalConfig.h"
#include "../core/json_storage.h"
#include "../core/encryption.h"

/**
 * @class MigrationHelper
 * @brief Handles migration of encrypted data when LFSR settings change
 * 
 * This class provides functionality to migrate stored credentials and master passwords
 * when the LFSR taps or initial state are modified. It ensures data consistency
 * across encryption setting changes.
 */
class MigrationHelper {
public:
    static MigrationHelper& getInstance();
    
    /**
     * @brief Migrate all credentials when LFSR settings change
     * 
     * @param oldTaps Previous LFSR tap configuration
     * @param oldInitState Previous LFSR initial state
     * @param newTaps New LFSR tap configuration
     * @param newInitState New LFSR initial state
     * @param masterPassword Master password for decryption/encryption
     * @param dataPath Path to data storage
     * @return bool True if migration was successful
     */
    bool migrateCredentialsForLfsrChange(
        const std::vector<int>& oldTaps,
        const std::vector<int>& oldInitState,
        const std::vector<int>& newTaps,
        const std::vector<int>& newInitState,
        const std::string& masterPassword,
        const std::string& dataPath
    );
    
    /**
     * @brief Update master password with new LFSR settings
     * 
     * @param oldTaps Previous LFSR tap configuration
     * @param oldInitState Previous LFSR initial state
     * @param newTaps New LFSR tap configuration
     * @param newInitState New LFSR initial state
     * @param masterPassword Master password for verification
     * @param dataPath Path to data storage
     * @return bool True if master password update was successful
     */
    bool updateMasterPasswordWithNewLfsr(
        const std::vector<int>& oldTaps,
        const std::vector<int>& oldInitState,
        const std::vector<int>& newTaps,
        const std::vector<int>& newInitState,
        const std::string& masterPassword,
        const std::string& dataPath
    );

        /**
     * @brief Migrate master password when encryption type changes (AES <-> LFSR)
     * @param oldType Previous encryption type
     * @param newType New encryption type
     * @param oldTaps Previous LFSR taps (if LFSR)
     * @param oldInitState Previous LFSR init state (if LFSR)
     * @param newTaps New LFSR taps (if LFSR)
     * @param newInitState New LFSR init state (if LFSR)
     * @param masterPassword Master password (plaintext)
     * @param dataPath Path to data storage
     * @return bool True if migration was successful
     */
    bool migrateMasterPasswordForEncryptionChange(
        EncryptionType oldType,
        EncryptionType newType,
        const std::vector<int>& oldTaps,
        const std::vector<int>& oldInitState,
        const std::vector<int>& newTaps,
        const std::vector<int>& newInitState,
        const std::string& masterPassword,
        const std::string& dataPath
    );

private:
    MigrationHelper() = default;
    
    /**
     * @brief Re-encrypt a single credential with new LFSR settings
     * 
     * @param platform Platform name for the credential
     * @param credentials Existing credential data [username, password, encryption_type]
     * @param oldEncryptor Encryptor with old settings
     * @param newEncryptor Encryptor with new settings
     * @param storage Storage instance for saving updated credentials
     * @return bool True if re-encryption was successful
     */
    bool reencryptCredential(
        const std::string& platform,
        const std::vector<std::string>& credentials,
        Encryption* oldEncryptor,
        Encryption* newEncryptor,
        JsonStorage* storage
    );
};

#endif // MIGRATION_HELPER_H
