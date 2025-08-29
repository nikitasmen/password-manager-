#ifndef MIGRATION_HELPER_H
#define MIGRATION_HELPER_H

#include <memory>
#include <random>
#include <string>
#include <vector>

#include "../core/encryption.h"
#include "../core/json_storage.h"
#include "../crypto/aes_encryption.h"
#include "../crypto/lfsr_encryption.h"
#include "GlobalConfig.h"

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
    bool migrateCredentialsForLfsrChange(const std::vector<int>& oldTaps,
                                         const std::vector<int>& oldInitState,
                                         const std::vector<int>& newTaps,
                                         const std::vector<int>& newInitState,
                                         const std::string& masterPassword,
                                         const std::string& dataPath);

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
    bool updateMasterPasswordWithNewLfsr(const std::vector<int>& oldTaps,
                                         const std::vector<int>& oldInitState,
                                         const std::vector<int>& newTaps,
                                         const std::vector<int>& newInitState,
                                         const std::string& masterPassword,
                                         const std::string& dataPath);

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
    bool migrateMasterPasswordForEncryptionChange(EncryptionType oldType,
                                                  EncryptionType newType,
                                                  const std::vector<int>& oldTaps,
                                                  const std::vector<int>& oldInitState,
                                                  const std::vector<int>& newTaps,
                                                  const std::vector<int>& newInitState,
                                                  const std::string& masterPassword,
                                                  const std::string& dataPath);

    /**
     * @brief Re-encrypt a single credential with new encryption settings
     *
     * @param platform Platform name for the credential
     * @param credentials Existing credential data
     * @param oldEncryptor Encryptor with old settings
     * @param newEncryptor Encryptor with new settings
     * @param storage Storage instance for saving updated credentials
     * @return bool True if re-encryption was successful
     */
    static bool reencryptCredential(const std::string& platform,
                                    const CredentialData& credentials,
                                    Encryption* oldEncryptor,
                                    Encryption* newEncryptor,
                                    JsonStorage* storage);

    std::string generateRandomSalt();

    /**
     * @brief Apply all settings from newConfig, comparing with oldConfig, and perform necessary migrations.
     *
     * This method should be called after settings are changed via the UI or config form.
     * It will:
     *  - Detect changes to default encryption, data path, and LFSR settings
     *  - Call appropriate migration/update methods for each change
     *  - Ensure all app data and config is consistent with the new settings
     *
     * @param oldConfig The previous (current) AppConfig
     * @param newConfig The updated AppConfig from the settings form
     * @param masterPassword The plaintext master password (required for migrations)
     * @return bool True if all migrations and updates succeeded
     */
    bool applySettingsFromConfig(const AppConfig& oldConfig,
                                 const AppConfig& newConfig,
                                 const std::string& masterPassword);

   private:
    static MigrationHelper instance_;
    MigrationHelper() = default;
};

#endif  // MIGRATION_HELPER_H
