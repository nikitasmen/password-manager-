#include "./api.h"
#include "../../GlobalConfig.h"
#include <fstream>
#include <iostream>

#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

extern std::vector<int> taps;
extern std::vector<int> init_state;

// Method definitions

CredentialsManager::CredentialsManager(const std::string& dataPath) : dataPath(dataPath), encryptor(taps, init_state) {
    // Make sure the directory exists
    fs::path dir(dataPath);
    if (!fs::exists(dir)) {
        fs::create_directories(dir);
        std::cout << "Created data directory: " << dataPath << std::endl;
    }
}

bool CredentialsManager::login(const std::string& password) {
    try {
        std::string correct, value;
        std::string loginFile = dataPath + "/enter"; // Use the dataPath specified in constructor
        
        std::cout << "Login attempt with data path: " << dataPath << std::endl;
        std::cout << "Checking login file: " << loginFile << std::endl;
        std::cout << "Checking if file exists: " << (fs::exists(loginFile) ? "yes" : "no") << std::endl;

        if (fs::exists(loginFile)) {
            std::ifstream fin(loginFile, std::ios::binary);
            if (!fin) {
                std::cerr << "Failed to open login file for reading: " << loginFile << std::endl;
                return false;
            }
            
            if (!getline(fin, value)) {
                std::cerr << "Failed to read encrypted value from file" << std::endl;
                return false;
            }
            fin.close();
            
            std::cout << "Encrypted value read: " << value << std::endl;
            correct = encryptor.decrypt(value);
            std::cout << "Decrypted value: " << correct << std::endl;
            std::cout << "Provided password: " << password << std::endl;
            
            bool match = (password == correct);
            std::cout << "Password match: " << (match ? "yes" : "no") << std::endl;
            return match;
        } else {
            std::cerr << "No existing password found. Please create one using the setup tool.\n";
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception during login: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::updatePassword(const std::string& newPassword) {
    try {
        std::cout << "Updating password in dataPath: " << dataPath << std::endl;
        std::string loginFile = dataPath + "/enter";
        
        // Ensure directory exists
        fs::path dirPath(dataPath);
        if (!fs::exists(dirPath)) {
            std::cout << "Creating directory: " << dataPath << std::endl;
            fs::create_directories(dirPath);
        }
        
        std::cout << "Opening file for writing: " << loginFile << std::endl;
        std::ofstream fout(loginFile, std::ofstream::out | std::ofstream::trunc);
        if (!fout) {
            std::cerr << "Failed to open file for writing: " << loginFile << std::endl;
            return false;
        }
        
        std::string encrypted = encryptor.encrypt(newPassword);
        std::cout << "Writing encrypted password to file" << std::endl;
        fout << encrypted;
        fout.close();
        
        // Verify the file was created
        if (!fs::exists(loginFile)) {
            std::cerr << "File was not created after writing: " << loginFile << std::endl;
            return false;
        }
        
        std::cout << "Password updated successfully" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Exception during password update: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::addCredentials(const std::string& platform, const std::string& user, const std::string& pass) {
    std::string platformName = dataPath + "/" + platform;
    
    // Check if platform already exists
    if (fs::exists(platformName)) {
        std::cerr << "Record already exists.\n";
        return false;
    }

    std::ofstream fout(platformName, std::ios::binary);
    if (!fout) {
        std::cerr << "Failed to create the record file.\n";
        return false;
    }

    fout << encryptor.encrypt(user) << "\n" << encryptor.encrypt(pass);
    fout.close();
    return true;
}

bool CredentialsManager::deleteCredentials(const std::string& platform) {
    std::string platformName = dataPath + "/" + platform;
    
    if (fs::exists(platformName)) {
        fs::remove(platformName);
        return true;
    } else {
        std::cerr << "Record does not exist.\n";
        return false;
    }
}

void CredentialsManager::showOptions(const std::string& path) const {
    if (!fs::exists(path) || !fs::is_directory(path)) {
        std::cerr << "Invalid directory path.\n";
        return;
    }

    std::cout << "Listing files in the directory:\n";
    for (const auto& file : fs::directory_iterator(path)) {
        if (file.is_regular_file()) {
            std::cout << file.path().filename().string() << std::endl;
        }
    }
}

std::vector<std::string> CredentialsManager::getAllPlatforms() {
    std::cout << "getAllPlatforms called with dataPath: " << dataPath << std::endl;
    std::vector<std::string> platforms;
    
    if (dataPath.empty()) {
        std::cerr << "Error: dataPath is empty!" << std::endl;
        return platforms;
    }
    
    // Check if directory exists
    if (!fs::exists(dataPath)) {
        std::cerr << "Error: dataPath directory doesn't exist: " << dataPath << std::endl;
        return platforms;
    }
    
    // Check if it's actually a directory
    if (!fs::is_directory(dataPath)) {
        std::cerr << "Error: dataPath is not a directory: " << dataPath << std::endl;
        return platforms;
    }
    
    try {
        std::cout << "Iterating directory: " << dataPath << std::endl;
        for (const auto& entry : fs::directory_iterator(dataPath)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                std::cout << "Found file: " << filename << std::endl;
                if (filename != "enter") {
                    std::cout << "Adding to platforms list: " << filename << std::endl;
                    platforms.push_back(filename);
                }
            }
        }
        
        std::cout << "Found " << platforms.size() << " platform(s)" << std::endl;
        return platforms;
    } catch (const std::exception& e) {
        std::cerr << "Exception while iterating directory: " << e.what() << std::endl;
        return platforms;
    }
}

std::vector<std::string> CredentialsManager::getCredentials(const std::string& platform) {
    std::vector<std::string> credentials;
    std::string platformName = dataPath + "/" + platform;
    
    if (!fs::exists(platformName)) {
        return credentials;
    }
    
    std::ifstream fin(platformName, std::ios::binary);
    if (!fin) {
        return credentials;
    }
    
    std::string encryptedUser, encryptedPass;
    if (getline(fin, encryptedUser) && getline(fin, encryptedPass)) {
        credentials.push_back(encryptor.decrypt(encryptedUser));
        credentials.push_back(encryptor.decrypt(encryptedPass));
    }
    
    fin.close();
    return credentials;
}


