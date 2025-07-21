#include "json_storage.h"
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <stdexcept>

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

// SafeFileHandler implementation
JsonStorage::SafeFileHandler::SafeFileHandler(const std::string& filename, std::ios::openmode mode) 
    : filename(filename), isOpen(false) {
    try {
        file.open(filename, mode);
        isOpen = file.is_open();
        if (!isOpen) {
            std::cerr << "Failed to open file: " << filename << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception opening file " << filename << ": " << e.what() << std::endl;
        isOpen = false;
    }
}

JsonStorage::SafeFileHandler::~SafeFileHandler() {
    close();
}

bool JsonStorage::SafeFileHandler::close() {
    if (isOpen && file.is_open()) {
        try {
            file.close();
            isOpen = false;
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Exception closing file " << filename << ": " << e.what() << std::endl;
            return false;
        }
    }
    return true;
}

bool JsonStorage::SafeFileHandler::flush() {
    if (isOpen && file.is_open()) {
        try {
            file.flush();
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Exception flushing file " << filename << ": " << e.what() << std::endl;
            return false;
        }
    }
    return false;
}

// Constructor implementation
JsonStorage::JsonStorage(const std::string& dataPath, const std::string& filename)
    : dataPath(dataPath), 
      storageFile((fs::path(dataPath) / filename).string()),
      masterPasswordKey("master_password"),
      modified(false) 
{
    ensureDataPathExists();
    // Initialize with empty data, will be loaded on first access
    credentialsData = nlohmann::json::object();
    // Load initial data
    loadData();
}

// Destructor implementation - save data if modified
JsonStorage::~JsonStorage() {
    if (modified) {
        std::cout << "Saving modified data on destruction..." << std::endl;
        if (!saveData()) {
            std::cerr << "Error: Failed to save data on destruction!" << std::endl;
        }
    }
}

bool JsonStorage::ensureDataPathExists() const {
    try {
        fs::path dir(dataPath);
        if (!fs::exists(dir)) {
            return fs::create_directories(dir);
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error creating directory: " << e.what() << std::endl;
        return false;
    }
}

bool JsonStorage::backupStorageFile() const {
    try {
        // Skip if file doesn't exist
        if (!fs::exists(storageFile)) {
            return true;
        }
        
        // Create timestamp for backup name
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y%m%d_%H%M%S");
        
        // Create backup name with timestamp
        std::string baseBackupName = storageFile + ".backup." + ss.str();
        std::string backupName = baseBackupName;
        
        // Handle duplicate backup names by adding an index
        int index = 1;
        while (fs::exists(backupName)) {
            backupName = baseBackupName + "_" + std::to_string(index);
            index++;
        }
        
        // Copy the file
        fs::copy_file(storageFile, backupName);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error creating backup: " << e.what() << std::endl;
        return false;
    }
}

bool JsonStorage::loadData() {
    try {
        // If file doesn't exist, keep the empty JSON object
        if (!fs::exists(storageFile)) {
            credentialsData = nlohmann::json::object();
            return true;
        }
        
        // Use SafeFileHandler for automatic file closing
        SafeFileHandler fileHandler(storageFile, std::ios::in);
        if (!fileHandler.is_open()) {
            std::cerr << "Failed to open storage file: " << storageFile << std::endl;
            return false;
        }
        
        try {
            // Read the entire file content first
            std::string content((std::istreambuf_iterator<char>(fileHandler.get())),
                               std::istreambuf_iterator<char>());
            
            // Ensure file is closed before parsing
            if (!fileHandler.close()) {
                std::cerr << "Warning: Failed to properly close file after reading" << std::endl;
            }
            
            // Parse JSON from the content
            if (!content.empty()) {
                credentialsData = nlohmann::json::parse(content);
            } else {
                credentialsData = nlohmann::json::object();
            }
        } catch (const nlohmann::json::parse_error& e) {
            std::cerr << "JSON parse error: " << e.what() << std::endl;
            credentialsData = nlohmann::json::object(); // Reset to empty on parse error
            fileHandler.close(); // Ensure file is closed on error
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading data: " << e.what() << std::endl;
        credentialsData = nlohmann::json::object(); // Reset to empty on error
        return false;
    }
}

bool JsonStorage::saveData() {
    try {
        // Create backup before saving
        backupStorageFile();
        
        // Create the directory if it doesn't exist
        ensureDataPathExists();
        
        // Use SafeFileHandler for automatic file closing
        SafeFileHandler fileHandler(storageFile, std::ios::out | std::ios::trunc);
        if (!fileHandler.is_open()) {
            std::cerr << "Failed to open storage file for writing: " << storageFile << std::endl;
            return false;
        }
        
        try {
            // Write JSON data to file
            fileHandler.get() << credentialsData.dump(4); // Pretty print with 4-space indent
            
            // Flush to ensure data is written to disk
            if (!fileHandler.flush()) {
                std::cerr << "Failed to flush data to disk" << std::endl;
                return false;
            }
            
            // Close file explicitly and check for errors
            if (!fileHandler.close()) {
                std::cerr << "Failed to properly close file after writing" << std::endl;
                return false;
            }
            
            modified = false; // Reset the modified flag only after successful write
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Error writing JSON data: " << e.what() << std::endl;
            fileHandler.close(); // Ensure file is closed on error
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error saving data: " << e.what() << std::endl;
        return false;
    }
}

std::string JsonStorage::getMasterPassword() const {
    try {
        // Create a temporary copy to work with
        nlohmann::json currentData;
        
        // Load fresh data from disk for this operation
        try {
            if (fs::exists(storageFile)) {
                SafeFileHandler fileHandler(storageFile, std::ios::in);
                if (fileHandler.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(fileHandler.get())),
                                        std::istreambuf_iterator<char>());
                    fileHandler.close();
                    
                    if (!content.empty()) {
                        currentData = nlohmann::json::parse(content);
                    } else {
                        currentData = nlohmann::json::object();
                    }
                } else {
                    // If can't open, use cached data
                    currentData = credentialsData;
                }
            } else {
                // If file doesn't exist, use cached data
                currentData = credentialsData;
            }
        } catch (const std::exception& e) {
            // If error reading, use cached data
            currentData = credentialsData;
        }
        
        if (currentData.contains(masterPasswordKey)) {
            std::string encodedPassword = currentData[masterPasswordKey];
            // Try to decode base64, fallback to raw if it fails
            try {
                return Base64::decode(encodedPassword);
            } catch (const std::exception& e) {
                std::cerr << "Base64 decode failed, treating as plaintext: " << e.what() << std::endl;
                return encodedPassword; // Return as-is for backward compatibility
            }
        }
        return "";
    } catch (const std::exception& e) {
        std::cerr << "Error retrieving master password: " << e.what() << std::endl;
        return "";
    }
}

bool JsonStorage::updateMasterPassword(const std::string& password) {
    try {
        if (password.empty()) {
            std::cerr << "Empty password provided" << std::endl;
            return false;
        }
        
        // Load the latest data before updating
        if (!loadData()) {
            std::cerr << "Failed to load data before updating master password" << std::endl;
        }
        
        // Encode the password in Base64 to ensure it's valid UTF-8 in JSON
        std::string encodedPassword = Base64::encode(password);
        credentialsData[masterPasswordKey] = encodedPassword;
        
        modified = true;
        return saveData(); // Save immediately for password changes
    } catch (const std::exception& e) {
        std::cerr << "Error updating master password: " << e.what() << std::endl;
        return false;
    }
}

bool JsonStorage::addCredentials(const std::string& platformName, 
                               const std::string& userName, 
                               const std::string& password,
                               int encryptionType) {
    try {
        // Input validation
        if (platformName.empty() || userName.empty() || password.empty()) {
            return false;
        }
        
        // Reload data to ensure we have the latest version
        if (!loadData()) {
            std::cerr << "Failed to reload data before adding credentials" << std::endl;
            return false;
        }
        
        // Check if platform already exists
        if (credentialsData.contains("platforms") && 
            credentialsData["platforms"].contains(platformName)) {
            return false;
        }
        
        // Initialize platforms object if it doesn't exist
        if (!credentialsData.contains("platforms")) {
            credentialsData["platforms"] = nlohmann::json::object();
        }
        
        // Encode credentials in Base64 to ensure they're valid UTF-8 in JSON
        std::string encodedUsername = Base64::encode(userName);
        std::string encodedPassword = Base64::encode(password);
        
        // Create platform entry with username and password
        nlohmann::json platform = {
            {"username", encodedUsername},
            {"password", encodedPassword},
            {"encryption_type", encryptionType}
        };
        
        // Add to credentials data
        credentialsData["platforms"][platformName] = platform;
        modified = true;
        
        // Immediately save to disk for transaction safety
        if (!saveData()) {
            std::cerr << "Failed to save credentials addition" << std::endl;
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error adding credentials: " << e.what() << std::endl;
        return false;
    }
}

bool JsonStorage::deleteCredentials(const std::string& platformName) {
    try {
        if (platformName.empty()) {
            return false;
        }
        
        // Reload data to ensure we have the latest version
        if (!loadData()) {
            std::cerr << "Failed to reload data before deleting credentials" << std::endl;
            return false;
        }
        
        // Check if platforms and the specific platform exist
        if (!credentialsData.contains("platforms") || 
            !credentialsData["platforms"].contains(platformName)) {
            return false;
        }
        
        // Remove the platform
        credentialsData["platforms"].erase(platformName);
        modified = true;
        
        // Immediately save to disk for transaction safety
        if (!saveData()) {
            std::cerr << "Failed to save credentials deletion" << std::endl;
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error deleting credentials: " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::string> JsonStorage::getAllPlatforms() const {
    std::vector<std::string> platforms;
    
    try {
        // Load fresh data for this operation
        nlohmann::json currentData;
        try {
            if (fs::exists(storageFile)) {
                SafeFileHandler fileHandler(storageFile, std::ios::in);
                if (fileHandler.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(fileHandler.get())),
                                        std::istreambuf_iterator<char>());
                    fileHandler.close();
                    
                    if (!content.empty()) {
                        currentData = nlohmann::json::parse(content);
                    } else {
                        currentData = nlohmann::json::object();
                    }
                } else {
                    // If can't open, use cached data
                    currentData = credentialsData;
                }
            } else {
                // If file doesn't exist, use cached data
                currentData = credentialsData;
            }
        } catch (const std::exception& e) {
            // If error reading, use cached data
            currentData = credentialsData;
        }
        
        // If platforms object exists, get all keys
        if (currentData.contains("platforms")) {
            for (const auto& [platform, _] : currentData["platforms"].items()) {
                platforms.push_back(platform);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error retrieving platforms: " << e.what() << std::endl;
    }
    
    return platforms;
}

std::vector<std::string> JsonStorage::getCredentials(const std::string& platformName) {
    std::vector<std::string> credentials;
    
    try {
        if (platformName.empty()) {
            return credentials;
        }
        
        // Reload data to ensure we have the latest version
        if (!loadData()) {
            std::cerr << "Failed to reload data before getting credentials" << std::endl;
            return credentials;
        }
        
        // Check if platforms and the specific platform exist
        if (credentialsData.contains("platforms") && 
            credentialsData["platforms"].contains(platformName)) {
            
            const auto& platform = credentialsData["platforms"][platformName];
            
            if (platform.contains("username") && platform.contains("password")) {
                std::string encodedUsername = platform["username"];
                std::string encodedPassword = platform["password"];
                
                // Get encryption type if available (default to 0 = LFSR for backward compatibility)
                std::string encType = "0";  // Default to LFSR
                if (platform.contains("encryption_type")) {
                    encType = std::to_string(platform["encryption_type"].get<int>());
                }
                
                // Try to decode Base64-encoded data
                try {
                    // Decode username (Base64 or raw)
                    std::string decodedUsername;
                    if (encodedUsername.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == 0) {
                        decodedUsername = Base64::decode(encodedUsername);
                    } else {
                        decodedUsername = encodedUsername; // Use as-is for backward compatibility
                    }
                    
                    // Decode password (Base64 or raw)
                    std::string decodedPassword;
                    if (encodedPassword.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == 0) {
                        decodedPassword = Base64::decode(encodedPassword);
                    } else {
                        decodedPassword = encodedPassword; // Use as-is for backward compatibility
                    }
                    
                    // Add credentials in correct order: [username, password, encryption_type]
                    credentials.push_back(decodedUsername);
                    credentials.push_back(decodedPassword);
                    credentials.push_back(encType);
                } catch (const std::exception& e) {
                    std::cerr << "Error decoding credentials: " << e.what() << std::endl;
                    // Fall back to raw values - maintain [username, password, encryption_type] order
                    credentials.clear();
                    credentials.push_back(encodedUsername);
                    credentials.push_back(encodedPassword);
                    credentials.push_back(encType);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error getting credentials: " << e.what() << std::endl;
    }
    
    return credentials;
}
