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
#include <memory>

/**
 * @class CredentialsManager
 * @brief Manages the storage and retrieval of encrypted credentials
 * 
 * This class provides functionality for managing passwords and credentials
 * including saving, loading, updating, and deleting credentials securely
 */
class CredentialsManager { 
    private: 
    std::string dataPath;                                  // Path to data storage directory
    EncryptionType encryptionType;                        // Current encryption algorithm
    std::unique_ptr<JsonStorage> storage;                 // Storage manager for credentials
    std::unique_ptr<Encryption> encryptor;               // Encryption engine for securing credentials
    bool isLoggedIn;                                     // Login state
    std::string masterPassword;                          // Master password for encryption

    public: 
        explicit CredentialsManager(const std::string& dataPath = ".", 
                                  EncryptionType encryptionType = EncryptionType::AES);
        ~CredentialsManager(); 
        
    // Prevent copying
    CredentialsManager(const CredentialsManager&) = delete;
    CredentialsManager& operator=(const CredentialsManager&) = delete;

    // Allow moving
    CredentialsManager(CredentialsManager&&) = default;
    CredentialsManager& operator=(CredentialsManager&&) = default;

    // Getters
        EncryptionType getEncryptionType() const { return encryptionType; }
    bool getIsLoggedIn() const { return isLoggedIn; }

    // Setters
        void setEncryptionType(EncryptionType type);
        
    // Core functionality
        bool login(const std::string& password);
        bool updatePassword(const std::string& newPassword);
        bool addCredentials(const std::string& platform, const std::string& user, const std::string& pass, 
                           std::optional<EncryptionType> encryptionType = std::nullopt);
        bool deleteCredentials(const std::string& platform);
    std::vector<std::string> getAllPlatforms();
        std::vector<std::string> getCredentials(const std::string& platform);
    bool hasMasterPassword() const;
};



#endif // API_H