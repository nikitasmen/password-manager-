#include "./encryption.h"
#include <fstream>
#include <iostream>
#include <filesystem>

// Assume these are initialized elsewhere
extern std::vector<int> taps;
extern std::vector<int> initState;
bool login(const std::string& password);
bool addCredentials(const std::string& platform, const std::string& user, const std::string& pass);
bool deleteCredentials(const std::string& platform);
void showOptions(const std::string& path = ".");
std::vector<std::string> getCredentials(const std::string& platform);


class CredentialManager {

private:
    std::string dataPath;
    Encryption encryptor;

public:
    explicit CredentialManager(const std::string& dataPath);
    bool login(const std::string& password);
    bool addCredentials(const std::string& platform, const std::string& user, const std::string& pass);
    bool deleteCredentials(const std::string& platform);
    void showOptions(const std::string& path = ".") const;
    std::vector<std::string> getCredentials(const std::string& platform);
};

// Method definitions

bool CredentialManager::login(const std::string& password) {
    Encryption log(taps, initState);
    std::string correct, value;
    std::string loginFile = "enter"; // Simplified for single command usage

    if (std::filesystem::exists(loginFile)) {
        std::ifstream fin(loginFile, std::ios::binary);
        getline(fin, value); // Read encrypted value
        fin.close();
        correct = log.decrypt(value);
        return password == correct;
    } else {
        std::cerr << "No existing password found. Please create one using the setup tool.\n";
        return false;
    }
}

bool CredentialManager::addCredentials(const std::string& platformName, const std::string& username, const std::string& password) {
    Encryption log(taps, initState);

    std::string filename = platformName;
    if (std::filesystem::exists(filename)) {
        std::cerr << "Record already exists.\n";
        return false;
    }

    std::ofstream fout(filename, std::ios::binary);
    if (!fout) {
        std::cerr << "Failed to create the record file.\n";
        return false;
    }

    fout << log.encrypt(username) << "\n" << log.encrypt(password);
    fout.close();
    return true;
}

bool CredentialManager::deleteCredentials(const std::string& platformName) {
    if (std::filesystem::exists(platformName)) {
        std::filesystem::remove(platformName);
        return true;
    } else {
        std::cerr << "Record does not exist.\n";
        return false;
    }
}

void CredentialManager::showOptions(const std::string& path) const {
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

std::vector<std::string> CredentialManager::getCredentials(const std::string& platformName) {
    Encryption dec(taps, initState);
    std::vector<std::string> credentials;
    std::string filename = platformName;
    std::ifstream fin(filename, std::ios::binary);

    if (!fin) {
        std::cerr << "Failed to open the file. Record does not exist.\n";
        return {};
    }

    std::string encryptedValue;
    while (getline(fin, encryptedValue)) {
        credentials.push_back(dec.decrypt(encryptedValue));
    }
    fin.close();
    return credentials;
}


