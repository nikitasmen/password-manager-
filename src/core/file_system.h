#ifndef DB_H
#define DB_H

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector> 
#include <string>
#include <stdexcept>

/**
 * @class DatabaseError
 * @brief Exception class for database operations
 */
class DatabaseError : public std::runtime_error {
public:
    explicit DatabaseError(const std::string& message) 
        : std::runtime_error("Database Error: " + message) {}
};

/**
 * @class Database
 * @brief Handles file operations for credentials storage
 * 
 * This class manages the persistent storage of credentials and passwords
 * providing a file system interface to the rest of the application
 */
class Database { 
private: 
    std::string dataPath;                      // Base path for data storage
    const std::string LOGIN_FILE = "enter";    // Master password file name
    std::string credentialsFile;               // Path to credentials storage

    /**
     * @brief Ensures the data directory exists
     * 
     * @return bool True if directory exists or was created
     */
    bool ensureDataPathExists() const;
    
    /**
     * @brief Create a backup of credentials file
     * 
     * @return bool True if backup was successful
     */
    bool backupCredentialsFile() const;

public:
    /**
     * @brief Construct a new Database object
     * 
     * @param dataPath Path where data files will be stored
     */
    explicit Database(const std::string& dataPath = "data");
    
    /**
     * @brief Get the master password from storage
     * 
     * @return std::string The stored password (may be encrypted)
     */
    std::string getPassword();
    
    /**
     * @brief Update the stored master password
     * 
     * @param password The new password to store
     * @return bool True if password was updated successfully
     */
    bool updatePassword(const std::string& password = "");
    
    /**
     * @brief Add new platform credentials
     * 
     * @param platformName Name of the platform/service
     * @param userName Username for the platform
     * @param password Password for the platform
     * @return bool True if credentials were added successfully
     */
    bool addCredentials(const std::string& platformName, const std::string& userName, const std::string& password);
    
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
    std::vector<std::string> getAllPlatforms();
    
    /**
     * @brief Get credentials for a specific platform
     * 
     * @param platformName Name of the platform
     * @return std::vector<std::string> Vector containing [username, password]
     */
    std::vector<std::string> getCredentials(const std::string& platformName);
}; 

#endif // DB_H