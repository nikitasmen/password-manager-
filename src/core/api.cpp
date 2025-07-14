#include "./api.h"
#include "./encryption.h" // Include the encryption header with EncryptionError
#include "../../GlobalConfig.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <algorithm> // For std::replace

// Use the appropriate filesystem library
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

extern std::vector<int> taps;
extern std::vector<int> init_state;

// Private helper methods for CredentialsManager

fs::path CredentialsManager::getPlatformPath(const std::string& platform) const {
    // Sanitize platform name to prevent path traversal
    std::string sanitized = platform;
    std::replace(sanitized.begin(), sanitized.end(), '/', '_');
    std::replace(sanitized.begin(), sanitized.end(), '\\', '_');
    std::replace(sanitized.begin(), sanitized.end(), '.', '_');
    
    return fs::path(dataPath) / sanitized;
}

bool CredentialsManager::ensureDataPathExists() const {
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

// Method implementations

CredentialsManager::CredentialsManager(const std::string& dataPath) 
    : dataPath(dataPath), encryptor(taps, init_state) {
    ensureDataPathExists();
}

bool CredentialsManager::login(const std::string& password) {
    try {
        std::cout << "Login attempt with password length: " << password.length() << std::endl;
        
        if (password.empty()) {
            std::cerr << "Error: Empty password provided\n";
            return false;
        }

        fs::path loginPath = fs::path(dataPath) / LOGIN_FILE;
        std::cout << "Using login file: " << loginPath.string() << std::endl;
        
        if (!fs::exists(loginPath)) {
            std::cerr << "No existing password found. Please create one using the setup tool.\n";
            return false;
        }

        std::ifstream fin(loginPath, std::ios::binary);
        if (!fin) {
            std::cerr << "Failed to open login file for reading: " << loginPath.string() << std::endl;
            return false;
        }
        
        std::string value;
        if (!getline(fin, value)) {
            std::cerr << "Failed to read encrypted value from file" << std::endl;
            return false;
        }
        fin.close();
        
        std::cout << "Read encrypted data with length: " << value.length() << std::endl;
        
        bool passwordMatched = false;
        
        // Handle simple case: plaintext password (for initial setup)
        if (value == password) {
            std::cout << "Using plaintext password match" << std::endl;
            passwordMatched = true;
        } else {
            // Try the salt-based method first
            try {
                std::string correct = encryptor.decryptWithSalt(value);
                bool saltPasswordMatch = (password == correct);
                std::cout << "Salt-based password check result: " << (saltPasswordMatch ? "SUCCESS" : "FAILED") << std::endl;
                
                if (saltPasswordMatch) {
                    passwordMatched = true;
                }
            } catch (const std::exception& e) {
                std::cerr << "Salt-based decryption failed: " << e.what() << std::endl;
                
                // Try legacy method only if salt method fails
                try {
                    std::string correct = encryptor.decrypt(value);
                    bool legacyPasswordMatch = (password == correct);
                    std::cout << "Legacy password check result: " << (legacyPasswordMatch ? "SUCCESS" : "FAILED") << std::endl;
                    
                    if (legacyPasswordMatch) {
                        passwordMatched = true;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Legacy decryption failed: " << e.what() << std::endl;
                }
            }
        }
        
        if (!passwordMatched) {
            std::cerr << "Authentication failed: Invalid password" << std::endl;
        }
        
        return passwordMatched;
    } catch (const std::exception& e) {
        std::cerr << "Exception during login: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::updatePassword(const std::string& newPassword) {
    try {
        if (newPassword.empty()) {
            std::cerr << "Error: Empty password provided\n";
            return false;
        }

        if (!ensureDataPathExists()) {
            return false;
        }
        
        fs::path loginPath = fs::path(dataPath) / LOGIN_FILE;
        
        // Create a new password file
        try {
            std::ofstream fout(loginPath, std::ofstream::out | std::ofstream::trunc | std::ios::binary);
            if (!fout) {
                std::cerr << "Failed to open file for writing: " << loginPath.string() << std::endl;
                return false;
            }
            
            // For very simple cases, just save plaintext
            if (newPassword.length() <= 3) {
                fout << newPassword;
                std::cout << "Using plain text storage for short passwords" << std::endl;
            } else {
                // Use enhanced encryption with salt for longer passwords
                std::string encrypted = encryptor.encryptWithSalt(newPassword);
                fout << encrypted;
                std::cout << "Password encrypted with salt, length: " << encrypted.length() << std::endl;
            }
            
            fout.close();
        } catch (const std::exception& e) {
            std::cerr << "Error writing password file: " << e.what() << std::endl;
            return false;
        }
        
        // Verify the file was created
        if (!fs::exists(loginPath)) {
            std::cerr << "File was not created after writing: " << loginPath.string() << std::endl;
            return false;
        }
        
        // Now let's verify we can read it back
        try {
            bool verifyResult = login(newPassword);
            if (!verifyResult) {
                std::cerr << "Warning: Password verification failed" << std::endl;
            } else {
                std::cout << "Password verification successful" << std::endl;
            }
        } catch (...) {
            // Ignore verification errors
        }
        
        return true;
    } catch (const EncryptionError& e) {
        std::cerr << "Encryption error during password update: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Exception during password update: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::addCredentials(const std::string& platform, const std::string& user, const std::string& pass) {
    try {
        if (platform.empty() || user.empty() || pass.empty()) {
            std::cerr << "Error: Empty platform, username, or password provided\n";
            return false;
        }

        if (!ensureDataPathExists()) {
            return false;
        }
        
        fs::path platformPath = getPlatformPath(platform);
        
        // Check if platform already exists
        if (fs::exists(platformPath)) {
            std::cerr << "Record for '" << platform << "' already exists.\n";
            return false;
        }

        std::ofstream fout(platformPath, std::ios::binary);
        if (!fout) {
            std::cerr << "Failed to create the record file: " << platformPath.string() << "\n";
            return false;
        }

        // Use enhanced encryption with salt
        std::string encryptedUser = encryptor.encryptWithSalt(user);
        std::string encryptedPass = encryptor.encryptWithSalt(pass);
        
        fout << encryptedUser << "\n" << encryptedPass;
        fout.close();
        
        // Verify file was created successfully
        if (!fs::exists(platformPath)) {
            std::cerr << "File was not created after writing: " << platformPath.string() << std::endl;
            return false;
        }
        
        return true;
    } catch (const EncryptionError& e) {
        std::cerr << "Encryption error while adding credentials: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Exception while adding credentials: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::deleteCredentials(const std::string& platform) {
    try {
        if (platform.empty()) {
            std::cerr << "Error: Empty platform name provided\n";
            return false;
        }
        
        fs::path platformPath = getPlatformPath(platform);
        
        if (fs::exists(platformPath)) {
            fs::remove(platformPath);
            return true;
        } else {
            std::cerr << "Record for '" << platform << "' does not exist.\n";
            return false;
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error while deleting credentials: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Exception while deleting credentials: " << e.what() << std::endl;
        return false;
    }
}

void CredentialsManager::showOptions(const std::string& path) const {
    try {
        fs::path dirPath = path.empty() ? fs::path(dataPath) : fs::path(path);
        
        if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
            std::cerr << "Invalid directory path: " << dirPath.string() << "\n";
            return;
        }

        std::cout << "Available platforms:\n";
        std::cout << "==================\n";
        
        bool foundFiles = false;
        for (const auto& entry : fs::directory_iterator(dirPath)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                if (filename != LOGIN_FILE) {
                    std::cout << "- " << filename << std::endl;
                    foundFiles = true;
                }
            }
        }
        
        if (!foundFiles) {
            std::cout << "No platforms found.\n";
        }
        std::cout << "==================\n";
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error while showing options: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Exception while showing options: " << e.what() << std::endl;
    }
}

std::vector<std::string> CredentialsManager::getAllPlatforms() {
    std::vector<std::string> platforms;
    
    try {
        if (dataPath.empty()) {
            std::cerr << "Error: dataPath is empty!" << std::endl;
            return platforms;
        }
        
        fs::path dirPath(dataPath);
        
        // Check if directory exists and is actually a directory
        if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
            std::cerr << "Error: Invalid dataPath: " << dataPath << std::endl;
            return platforms;
        }
        
        for (const auto& entry : fs::directory_iterator(dirPath)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                if (filename != LOGIN_FILE) {
                    platforms.push_back(filename);
                }
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error while getting platforms: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Exception while getting platforms: " << e.what() << std::endl;
    }
    
    return platforms;
}

std::vector<std::string> CredentialsManager::getCredentials(const std::string& platform) {
    std::vector<std::string> credentials;
    
    try {
        if (platform.empty()) {
            std::cerr << "Error: Empty platform name provided\n";
            return credentials;
        }
        
        fs::path platformPath = getPlatformPath(platform);
        
        if (!fs::exists(platformPath)) {
            std::cerr << "Record for '" << platform << "' does not exist.\n";
            return credentials;
        }
        
        std::ifstream fin(platformPath, std::ios::binary);
        if (!fin) {
            std::cerr << "Failed to open platform file: " << platformPath.string() << "\n";
            return credentials;
        }
        
        std::string encryptedUser, encryptedPass;
        if (getline(fin, encryptedUser) && getline(fin, encryptedPass)) {
            try {
                // Use salt-aware decryption
                credentials.push_back(encryptor.decryptWithSalt(encryptedUser));
                credentials.push_back(encryptor.decryptWithSalt(encryptedPass));
            } catch (const EncryptionError& e) {
                std::cerr << "Encryption error while decrypting credentials: " << e.what() << std::endl;
                
                // Fallback to legacy decryption if salt-aware fails
                try {
                    credentials.clear();
                    credentials.push_back(encryptor.decrypt(encryptedUser));
                    credentials.push_back(encryptor.decrypt(encryptedPass));
                } catch (const EncryptionError& e2) {
                    std::cerr << "Legacy decryption also failed: " << e2.what() << std::endl;
                    return std::vector<std::string>();
                }
            }
        } else {
            std::cerr << "Failed to read credentials from file: " << platformPath.string() << "\n";
        }
        
        fin.close();
    } catch (const std::exception& e) {
        std::cerr << "Exception while getting credentials: " << e.what() << std::endl;
    }
    
    return credentials;
}


