#ifndef JSON_STORAGE_H
#define JSON_STORAGE_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <fstream>
#include <nlohmann/json.hpp>
#include "./base64.h"

/**
 * @class JsonStorage
 * @brief Provides JSON-based persistent storage for credentials
 * 
 * This class manages the storage of credentials in a single JSON file,
 * improving organization and allowing for more structured data management.
 */
class JsonStorage {
private:
    std::string dataPath;                      // Base path for data storage
    std::string storageFile;                   // Path to JSON storage file
    std::string masterPasswordKey;             // Key for master password in JSON
    nlohmann::json credentialsData;            // In-memory representation of credentials
    bool modified;                             // Flag to track if data has been modified

    /**
     * @brief RAII wrapper for safe file operations
     */
    class SafeFileHandler {
    private:
        std::fstream file;
        std::string filename;
        bool isOpen;
        
    public:
        SafeFileHandler(const std::string& filename, std::ios::openmode mode);
        ~SafeFileHandler();
        
        bool is_open() const { return isOpen && file.is_open(); }
        std::fstream& get() { return file; }
        bool close();
        bool flush();
    };

    /**
     * @brief Ensures the data directory exists
     * 
     * @return bool True if directory exists or was created
     */
    bool ensureDataPathExists() const;
    
    /**
     * @brief Create a backup of storage file
     * 
     * @return bool True if backup was successful
     */
    bool backupStorageFile() const;
    
    /**
     * @brief Load data from storage file into memory
     * 
     * @return bool True if data was loaded successfully
     */
    bool loadData();
    
    /**
     * @brief Save in-memory data to storage file
     * 
     * @return bool True if data was saved successfully
     */
    bool saveData();

public:
    /**
     * @brief Construct a new JsonStorage object
     * 
     * @param dataPath Path where data files will be stored
     * @param filename Name of the JSON storage file
     */
    JsonStorage(const std::string& dataPath = "data", 
               const std::string& filename = "secure_storage.json");
    
    /**
     * @brief Destructor to ensure data is saved
     */
    ~JsonStorage();
    
    /**
     * @brief Get the master password from storage
     * 
     * @return std::string The stored password (may be encrypted)
     */
    std::string getMasterPassword() const;
    
    /**
     * @brief Update the stored master password
     * 
     * @param password The new password to store
     * @return bool True if password was updated successfully
     */
    bool updateMasterPassword(const std::string& password);
    
    /**
     * @brief Add new platform credentials
     * 
     * @param platformName Name of the platform/service
     * @param userName Username for the platform
     * @param password Password for the platform
     * @return bool True if credentials were added successfully
     */
    bool addCredentials(const std::string& platformName, 
                       const std::string& userName, 
                       const std::string& password);
    
    /**
     * @brief Delete stored credentials for a platform
     * 
     * @param platformName Name of the platform to delete
     * @return bool True if credentials were deleted successfully
     */
    bool deleteCredentials(const std::string& platformName);
    
    /**
     * @brief Get all stored platform names
     * 
     * @return std::vector<std::string> List of platform names
     */
    std::vector<std::string> getAllPlatforms() const;
    
    /**
     * @brief Get credentials for a specific platform
     * 
     * @param platformName Name of the platform
     * @return std::vector<std::string> Vector containing [username, password]
     */
    std::vector<std::string> getCredentials(const std::string& platformName);
};

#endif // JSON_STORAGE_H
