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
        explicit CredentialsManager(const std::string& dataPath = "."); 
        bool login(const std::string& password);
        bool updatePassword(const std::string& newPassword);
        bool addCredentials(const std::string& platform, const std::string& user, const std::string& pass); 
        bool deleteCredentials(const std::string& platform);
        void showOptions(const std::string& path = ".") const;
        std::vector<std::string> getCredentials(const std::string& platform);
        std::vector<std::string> getAllPlatforms();
}; 



#endif // API_H