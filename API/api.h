#ifndef API_H
#define API_H

#include <filesystem>
#include <fstream>
#include <iostream>
#include "Encryption.h"

class CredentialsManager{ 
    private: 
        std::string dataPath;
        Encryption encryptor;
    public: 
        // CredentialsMAnager(const std::string& dataPath); 
        bool login(const std::string& password);




}



#endif // API_H