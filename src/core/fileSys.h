#ifndef DB_H
#define DB_H

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector> 
#include <string>
#include "../data/data.h"

class Database { 
    private: 
        std::string dataPath;
    public: 
        // Database(const std::string& dataPath); 
        std::string getPassword(); 
        bool updatePassword(const std::string& password = "");
        bool addCredentials(const std::string& platformName, const std::string& userName, const std::string& password);
        bool deleteCredentials(const std::string& platformName);
        std::vector<std::string> getAllPlatforms();
        std::vector<std::string> getCredentials(const std::string& platformName);
        
}; 


#endif // DB_H 