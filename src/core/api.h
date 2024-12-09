#ifndef API_H
#define API_H

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector> 
#include "./encryption.h"

class CredentialsManager{ 
    private: 
        std::string dataPath;
        Encryption encryptor;
    public: 
        // CredentialsMAnager(const std::string& dataPath); 
        bool CredentialsManager::login(const std::string& password);
        bool CredentialsManager::addCredentials(const std::string& platform, const std::string& user, const std::string& pass); 
        bool CredentialsManager::deleteCredentials(const std::string& platform);
        void CredentialsManager::showOptions(const std::string& path = ".") const;
        std::vector<std::string> CredentialsManager::getCredentials(const std::string& platform);

}; 



#endif // API_H