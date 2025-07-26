#ifndef API_H
#define API_H

#include <filesystem>
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <optional>
#include <memory>
#include "./encryption.h"
#include "./json_storage.h"
#include "../crypto/encryption_factory.h"

/**
 * @class CredentialsManager
 * @brief Manages the storage and retrieval of encrypted credentials
 * 
 * This class provides functionality for managing passwords and credentials
 * including saving, loading, updating, and deleting credentials securely
 */
class CredentialsManager { 
private: 
    std::string dataPath;                  // Path where data files are stored
    std::unique_ptr<IEncryption> encryptor; // Encryption engine for securing credentials
    JsonStorage* storage;                  // Storage engine for credentials - dynamically allocated
    EncryptionType encryptionType;         // Current encryption algorithm
    std::string currentMasterPassword;     // Stores the current master password in memory
    std::vector<int> lfsrTaps;             // LFSR taps for encryption
    std::vector<int> lfsrInitState;        // LFSR initial state for encryption
    
    // Create a new encryptor with current settings
    void createEncryptor(EncryptionType type, const std::string& password);
    
public:
    /**
     * @brief Construct a new Credentials Manager object
     * 
     * @param dataPath Path to the directory where credential data will be stored
     * @param encryptionType The encryption algorithm to use (default: from config)
     */
    explicit CredentialsManager(const std::string& dataPath, 
                              EncryptionType encryptionType = ConfigManager::getInstance().getDefaultEncryption());
    
    // Disable copy and assignment
    CredentialsManager(const CredentialsManager&) = delete;
    CredentialsManager& operator=(const CredentialsManager&) = delete;
    
    /**
     * @brief Destroy the Credentials Manager object
     * Properly cleans up dynamically allocated memory
     */
    ~CredentialsManager();
    
    /**
     * @brief Authenticate with the master password
     * 
     * @param password The master password to authenticate with
     * @return true if authentication is successful, false otherwise
     */
    bool login(const std::string& password);
    
    /**
     * @brief Update the master password
     * 
     * @param newPassword The new master password
     * @return true if the password was updated successfully, false otherwise
     */
    bool updatePassword(const std::string& newPassword);
    
    /**
     * @brief Add or update credentials for a platform
     * 
     * @param platform The platform/service name (e.g., "GitHub", "Gmail")
     * @param user The username/email for the platform
     * @param pass The password to store (will be encrypted)
     * @param encryptionType Optional encryption type to use for this credential
     * @return true if the credentials were saved successfully, false otherwise
     */
    bool addCredentials(const std::string& platform, const std::string& user, 
                       const std::string& pass, 
                       std::optional<EncryptionType> encryptionType = std::nullopt);
    
    /**
     * @brief Delete credentials for a platform
     * 
     * @param platform The platform to delete credentials for
     * @return true if the credentials were deleted, false if an error occurred
     */
    bool deleteCredentials(const std::string& platform);
    
    /**
     * @brief Get the stored credentials for a platform
     * 
     * @param platform The platform to get credentials for
     * @return std::vector<std::string> Vector containing [username, password, encryption_type]
     *         where encryption_type is the string representation of EncryptionType
     */
    std::vector<std::string> getCredentials(const std::string& platform);
    
    /**
     * @brief Check if a master password is set
     * 
     * @return true if a master password is set, false otherwise
     */
    bool hasMasterPassword() const;
    
    /**
     * @brief Set the encryption type for new credentials
     * 
     * @param type The encryption type to use
     */
    void setEncryptionType(EncryptionType type);
    
    /**
     * @brief Get the current encryption type
     * 
     * @return EncryptionType The current encryption type
     */
    EncryptionType getEncryptionType() const { return encryptionType; }
    
    /**
     * @brief Get all platform names that have stored credentials
     * 
     * @return std::vector<std::string> Vector of platform names
     */
    std::vector<std::string> getAllPlatforms() const;
};



#endif // API_H