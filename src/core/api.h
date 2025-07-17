#ifndef API_H
#define API_H

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <optional>
#include "./encryption.h"
#include "./json_storage.h"

/**
 * @class CredentialsManager
 * @brief Manages the storage and retrieval of encrypted credentials
 * 
 * This class provides functionality for managing passwords and credentials
 * including saving, loading, updating, and deleting credentials securely
 */
class CredentialsManager { 
    private: 
        std::string dataPath;               // Path where data files are stored
        Encryption* encryptor;              // Encryption engine for securing credentials - dynamically allocated
        JsonStorage* storage;               // Storage engine for credentials - dynamically allocated
        EncryptionType encryptionType;      // Current encryption algorithm
        std::string currentMasterPassword;  // Current master password for AES encryption
        
        // Disable copy constructor and assignment operator to prevent issues
        CredentialsManager(const CredentialsManager&) = delete;
        CredentialsManager& operator=(const CredentialsManager&) = delete;

    public: 
        /**
         * @brief Check if a master password exists in storage
         * 
         * @return bool True if a master password exists
         */
        bool hasMasterPassword() const;

        /**
         * @brief Construct a new Credentials Manager object
         * 
         * @param dataPath Path where credential data will be stored
         * @param encryptionType The encryption algorithm to use
         */
        explicit CredentialsManager(const std::string& dataPath = ".", 
                                  EncryptionType encryptionType = g_encryption_type);
        
        /**
         * @brief Destroy the Credentials Manager object and free allocated memory
         */
        ~CredentialsManager(); 
        
        /**
         * @brief Get current encryption algorithm
         * 
         * @return EncryptionType The current encryption algorithm
         */
        EncryptionType getEncryptionType() const { return encryptionType; }
        
        /**
         * @brief Set encryption algorithm
         * 
         * @param type The new encryption algorithm to use
         */
        void setEncryptionType(EncryptionType type);
        
        /**
         * @brief Verify login credentials
         * 
         * @param password Master password to verify
         * @return bool True if login is successful
         */
        bool login(const std::string& password);
        
        /**
         * @brief Update the master password
         * 
         * @param newPassword New password to set
         * @return bool True if password was updated successfully
         */
        bool updatePassword(const std::string& newPassword);
        
        /**
         * @brief Add new credentials for a platform
         * 
         * @param platform Platform name
         * @param user Username for the platform
         * @param pass Password for the platform
         * @param encryptionType The encryption algorithm to use (default: current global setting)
         * @return bool True if credentials were added successfully
         */
        bool addCredentials(const std::string& platform, const std::string& user, const std::string& pass, 
                           std::optional<EncryptionType> encryptionType = std::nullopt);
        
        /**
         * @brief Delete credentials for a platform
         * 
         * @param platform Platform name to delete
         * @return bool True if credentials were deleted successfully
         */
        bool deleteCredentials(const std::string& platform);
        
        /**
         * @brief Show available platforms in the given path
         * 
         * @param path Path to search for credential files
         */
        void showOptions(const std::string& path = ".") const;
        
        /**
         * @brief Get credentials for a specific platform
         * 
         * @param platform Platform name to retrieve
         * @return std::vector<std::string> Vector containing [username, password, encryption_type]
         *         where encryption_type is "0" for LFSR or "1" for AES
         */
        std::vector<std::string> getCredentials(const std::string& platform);
        
        /**
         * @brief Get all platforms that have stored credentials
         * 
         * @return std::vector<std::string> List of platform names
         */
        std::vector<std::string> getAllPlatforms();
};



#endif // API_H