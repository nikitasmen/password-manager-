#include "./fileSys.h"
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

// Constructor implementation
Database::Database(const std::string& dataPath) : dataPath(dataPath) {
    credentialsFile = (fs::path(dataPath) / "credentials").string();
    ensureDataPathExists();
}

bool Database::ensureDataPathExists() const {
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

bool Database::backupCredentialsFile() const {
    try {
        // Skip if file doesn't exist
        if (!fs::exists(credentialsFile)) {
            return true;
        }
        
        // Create timestamp for backup name
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y%m%d_%H%M%S");
        
        // Create backup name with timestamp
        std::string backupName = credentialsFile + ".backup." + ss.str();
        
        // Copy the file
        fs::copy_file(credentialsFile, backupName);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error creating backup: " << e.what() << std::endl;
        return false;
    }
}

std::string Database::getPassword() {
    try {
        std::string password;
        fs::path loginPath = fs::path(dataPath) / LOGIN_FILE;
        
        if (fs::exists(loginPath)) {
            std::ifstream fin(loginPath, std::ios::binary);
            if (!fin) {
                throw DatabaseError("Failed to open login file for reading: " + loginPath.string());
            }
            
            if (!std::getline(fin, password)) {
                throw DatabaseError("Failed to read password from file: " + loginPath.string());
            }
            fin.close();
        }
        return password;
    } catch (const DatabaseError& e) {
        throw; // Re-throw database-specific errors
    } catch (const std::exception& e) {
        throw DatabaseError("Error retrieving password: " + std::string(e.what()));
    }
}

bool Database::updatePassword(const std::string& password) {
    try {
        if (password.empty()) {
            throw DatabaseError("Empty password provided");
        }
        
        ensureDataPathExists();
        
        fs::path loginPath = fs::path(dataPath) / LOGIN_FILE;
        
        std::ofstream fout(loginPath, std::ofstream::out | std::ofstream::trunc | std::ios::binary);
        if (!fout) {
            throw DatabaseError("Failed to open login file for writing: " + loginPath.string());
        }
        
        fout << password;
        fout.close();
        
        return true;
    } catch (const DatabaseError& e) {
        std::cerr << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error updating password: " << e.what() << std::endl;
        return false;
    }
}

bool Database::addCredentials(const std::string& platformName, const std::string& userName, const std::string& password) {
    try {
        // Input validation
        if (platformName.empty() || userName.empty() || password.empty()) {
            throw DatabaseError("Empty platform name, username, or password");
        }
        
        // Sanitize platform name
        std::string sanitizedName = platformName;
        std::replace(sanitizedName.begin(), sanitizedName.end(), '\n', '_');
        
        // Check if platform already exists
        std::vector<std::string> platforms = getAllPlatforms();
        for (const std::string& platform : platforms) {
            if (platform == sanitizedName) {
                throw DatabaseError("Platform '" + platformName + "' already exists");
            }
        }
        
        ensureDataPathExists();
        
        // Create backup before modification
        backupCredentialsFile();
        
        // Add new platform credentials
        std::ofstream fout(credentialsFile, std::ios::app | std::ios::binary);
        if (!fout) {
            throw DatabaseError("Failed to open credentials file for writing: " + credentialsFile);
        }
        
        fout << sanitizedName << "\n" << userName << "\n" << password << "\n";
        fout.close();
        
        return true;
    } catch (const DatabaseError& e) {
        std::cerr << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error adding credentials: " << e.what() << std::endl;
        return false;
    }
}

bool Database::deleteCredentials(const std::string& platformName) {
    try {
        if (platformName.empty()) {
            throw DatabaseError("Empty platform name provided");
        }
        
        // Create backup before modification
        backupCredentialsFile();
        
        std::vector<std::string> platforms;
        std::vector<std::string> usernames;
        std::vector<std::string> passwords;
        bool found = false;
        
        std::ifstream fin(credentialsFile);
        if (!fin) {
            throw DatabaseError("Failed to open credentials file for reading: " + credentialsFile);
        }
        
        std::string platform, username, password;
        while (std::getline(fin, platform) && std::getline(fin, username) && std::getline(fin, password)) {
            if (platform != platformName) {
                platforms.push_back(platform);
                usernames.push_back(username);
                passwords.push_back(password);
            } else {
                found = true; // Mark as found
            }
        }
        fin.close();
        
        if (!found) {
            throw DatabaseError("Platform '" + platformName + "' not found");
        }
        
        // Write back all credentials except the deleted one
        std::ofstream fout(credentialsFile, std::ofstream::out | std::ofstream::trunc | std::ios::binary);
        if (!fout) {
            throw DatabaseError("Failed to open credentials file for writing: " + credentialsFile);
        }
        
        for (size_t i = 0; i < platforms.size(); i++) {
            fout << platforms[i] << "\n" << usernames[i] << "\n" << passwords[i] << "\n";
        }
        fout.close();
        
        return true;
    } catch (const DatabaseError& e) {
        std::cerr << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error deleting credentials: " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::string> Database::getAllPlatforms() {
    std::vector<std::string> platforms;
    
    try {
        if (!fs::exists(credentialsFile)) {
            return platforms; // Empty vector if file doesn't exist
        }
        
        std::ifstream fin(credentialsFile);
        if (!fin) {
            throw DatabaseError("Failed to open credentials file for reading: " + credentialsFile);
        }
        
        std::string platform, username, password;
        while (std::getline(fin, platform) && std::getline(fin, username) && std::getline(fin, password)) {
            platforms.push_back(platform);
        }
        fin.close();
    } catch (const std::exception& e) {
        std::cerr << "Error retrieving platforms: " << e.what() << std::endl;
    }
    
    return platforms;
}

std::vector<std::string> Database::getCredentials(const std::string& platformName) {
    std::vector<std::string> credentials;
    
    try {
        if (platformName.empty()) {
            throw DatabaseError("Empty platform name provided");
        }
        
        if (!fs::exists(credentialsFile)) {
            return credentials; // Return empty vector if file doesn't exist
        }
        
        std::ifstream fin(credentialsFile);
        if (!fin) {
            throw DatabaseError("Failed to open credentials file for reading: " + credentialsFile);
        }
        
        std::string platform, username, password;
        bool found = false;
        
        while (std::getline(fin, platform) && std::getline(fin, username) && std::getline(fin, password)) {
            if (platform == platformName) {
                credentials.push_back(username);
                credentials.push_back(password);
                found = true;
                break; // Stop after finding the first match
            }
        }
        fin.close();
        
        if (!found) {
            std::cerr << "Platform '" << platformName << "' not found" << std::endl;
        }
    } catch (const DatabaseError& e) {
        std::cerr << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error retrieving credentials: " << e.what() << std::endl;
    }
    
    return credentials;
}