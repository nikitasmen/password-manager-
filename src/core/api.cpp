#include "./api.h"
#include "../../GlobalConfig.h"
#include <fstream>
#include <iostream>
#include <filesystem>

extern std::vector<int> taps;
extern std::vector<int> init_state;

// Method definitions

CredentialsManager::CredentialsManager(const std::string& dataPath) : dataPath(dataPath), encryptor(taps, init_state) {
}

bool CredentialsManager::login(const std::string& password) {
    std::string correct, value;
    std::string loginFile = "enter"; // Simplified for single command usage

    if (std::filesystem::exists(loginFile)) {
        std::ifstream fin(loginFile, std::ios::binary);
        getline(fin, value); // Read encrypted value
        fin.close();
        correct = encryptor.decrypt(value);
        return password == correct;
    } else {
        std::cerr << "No existing password found. Please create one using the setup tool.\n";
        return false;
    }
}

bool CredentialsManager::updatePassword(const std::string& newPassword) {
    std::string loginFile = "enter";
    std::ofstream fout(loginFile, std::ofstream::out | std::ofstream::trunc);
    if (!fout) {
        return false;
    }
    fout << encryptor.encrypt(newPassword);
    fout.close();
    return true;
}

bool CredentialsManager::addCredentials(const std::string& platform, const std::string& user, const std::string& pass) {
    std::string platformName = platform;
    
    // Check if platform already exists
    if (std::filesystem::exists(platformName)) {
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
    std::string platformName = platform;
    
    if (std::filesystem::exists(platformName)) {
        std::filesystem::remove(platformName);
        return true;
    } else {
        std::cerr << "Record does not exist.\n";
        return false;
    }
}

void CredentialsManager::showOptions(const std::string& path) const {
    if (!std::filesystem::exists(path) || !std::filesystem::is_directory(path)) {
        std::cerr << "Invalid directory path.\n";
        return;
    }

    std::cout << "Listing files in the directory:\n";
    for (const auto& file : std::filesystem::directory_iterator(path)) {
        if (file.is_regular_file()) {
            std::cout << file.path().filename().string() << std::endl;
        }
    }
}

std::vector<std::string> CredentialsManager::getAllPlatforms() {
    std::vector<std::string> platforms;
    
    for (const auto& entry : std::filesystem::directory_iterator(dataPath)) {
        if (entry.is_regular_file() && entry.path().filename() != "enter") {
            platforms.push_back(entry.path().filename().string());
        }
    }
    
    return platforms;
}

std::vector<std::string> CredentialsManager::getCredentials(const std::string& platform) {
    std::vector<std::string> credentials;
    std::string platformName = platform;
    
    if (!std::filesystem::exists(platformName)) {
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


