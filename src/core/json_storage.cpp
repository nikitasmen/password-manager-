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

// Constructor implementation
JsonStorage::JsonStorage(const std::string& dataPath, const std::string& filename)
    : dataPath(dataPath), 
      storageFile((fs::path(dataPath) / filename).string()),
      masterPasswordKey("master_password"),
      modified(false) 
{
    ensureDataPathExists();
    loadData();
}

// Destructor implementation - save data if modified
JsonStorage::~JsonStorage() {
    if (modified) {
        saveData();
    }
}

bool JsonStorage::ensureDataPathExists() const {
    try {
        fs::path dir(dataPath);
        if (!fs::exists(dir)) {
            return fs::create_directories(dir);
        }
        return true;
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return false;
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
        std::string backupName = storageFile + ".backup." + ss.str();
        
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
        // If file doesn't exist, start with empty JSON object
        if (!fs::exists(storageFile)) {
            credentialsData = nlohmann::json::object();
            return true;
        }
        
        // Open and read the file
        std::ifstream file(storageFile);
        if (!file.is_open()) {
            std::cerr << "Failed to open storage file: " << storageFile << std::endl;
            return false;
        }
        
        try {
            file >> credentialsData;
        } catch (const nlohmann::json::parse_error& e) {
            std::cerr << "JSON parse error: " << e.what() << std::endl;
            credentialsData = nlohmann::json::object(); // Reset to empty on parse error
            return false;
        }
        
        file.close();
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
        
        // Write the JSON to the file with pretty formatting
        std::ofstream file(storageFile);
        if (!file.is_open()) {
            std::cerr << "Failed to open storage file for writing: " << storageFile << std::endl;
            return false;
        }
        
        file << credentialsData.dump(4); // Pretty print with 4-space indent
        file.close();
        
        modified = false; // Reset the modified flag
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving data: " << e.what() << std::endl;
        return false;
    }
}

std::string JsonStorage::getMasterPassword() const {
    try {
        if (credentialsData.contains(masterPasswordKey)) {
            std::string encodedPassword = credentialsData[masterPasswordKey];
            // If the password is base64-encoded, decode it first
            if (encodedPassword.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == 0) {
                try {
                    return Base64::decode(encodedPassword);
                } catch (const std::exception& e) {
                    std::cerr << "Failed to decode password, treating as raw: " << e.what() << std::endl;
                    return encodedPassword; // Return as-is for backward compatibility
                }
            }
            return encodedPassword; // Return as-is for backward compatibility
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
        
        // Encode the password in Base64 to ensure it's valid UTF-8 in JSON
        std::string encodedPassword = Base64::encode(password);
        credentialsData[masterPasswordKey] = encodedPassword;
        
        std::cout << "Encoded master password for storage" << std::endl;
        
        modified = true;
        return saveData(); // Save immediately for password changes
    } catch (const std::exception& e) {
        std::cerr << "Error updating master password: " << e.what() << std::endl;
        return false;
    }
}

bool JsonStorage::addCredentials(const std::string& platformName, 
                               const std::string& userName, 
                               const std::string& password) {
    try {
        // Input validation
        if (platformName.empty() || userName.empty() || password.empty()) {
            std::cerr << "Empty platform name, username, or password" << std::endl;
            return false;
        }
        
        // Check if platform already exists
        if (credentialsData.contains("platforms") && 
            credentialsData["platforms"].contains(platformName)) {
            std::cerr << "Platform '" << platformName << "' already exists" << std::endl;
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
            {"password", encodedPassword}
        };
        
        // Add to credentials data
        credentialsData["platforms"][platformName] = platform;
        modified = true;
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error adding credentials: " << e.what() << std::endl;
        return false;
    }
}

bool JsonStorage::deleteCredentials(const std::string& platformName) {
    try {
        if (platformName.empty()) {
            std::cerr << "Empty platform name provided" << std::endl;
            return false;
        }
        
        // Check if platforms and the specific platform exist
        if (!credentialsData.contains("platforms") || 
            !credentialsData["platforms"].contains(platformName)) {
            std::cerr << "Platform '" << platformName << "' not found" << std::endl;
            return false;
        }
        
        // Remove the platform
        credentialsData["platforms"].erase(platformName);
        modified = true;
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error deleting credentials: " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::string> JsonStorage::getAllPlatforms() const {
    std::vector<std::string> platforms;
    
    try {
        // If platforms object exists, get all keys
        if (credentialsData.contains("platforms")) {
            for (const auto& [platform, _] : credentialsData["platforms"].items()) {
                platforms.push_back(platform);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error retrieving platforms: " << e.what() << std::endl;
    }
    
    return platforms;
}

std::vector<std::string> JsonStorage::getCredentials(const std::string& platformName) const {
    std::vector<std::string> credentials;
    
    try {
        if (platformName.empty()) {
            std::cerr << "Empty platform name provided" << std::endl;
            return credentials;
        }
        
        // Check if platforms and the specific platform exist
        if (credentialsData.contains("platforms") && 
            credentialsData["platforms"].contains(platformName)) {
            
            const auto& platform = credentialsData["platforms"][platformName];
            
            if (platform.contains("username") && platform.contains("password")) {
                std::string encodedUsername = platform["username"];
                std::string encodedPassword = platform["password"];
                
                // Try to decode Base64-encoded data
                try {
                    // Check if the stored values appear to be Base64 encoded
                    if (encodedUsername.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == 0) {
                        credentials.push_back(Base64::decode(encodedUsername));
                    } else {
                        credentials.push_back(encodedUsername); // Use as-is for backward compatibility
                    }
                    
                    if (encodedPassword.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == 0) {
                        credentials.push_back(Base64::decode(encodedPassword));
                    } else {
                        credentials.push_back(encodedPassword); // Use as-is for backward compatibility
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error decoding credentials (using raw values): " << e.what() << std::endl;
                    credentials.push_back(encodedUsername);
                    credentials.push_back(encodedPassword);
                }
            }
        } else {
            std::cerr << "Platform '" << platformName << "' not found" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error retrieving credentials: " << e.what() << std::endl;
    }
    
    return credentials;
}
