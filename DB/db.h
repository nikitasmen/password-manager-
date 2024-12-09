#ifndef DB_H
#define DB_H

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector> 
#include "../Data/enter"

class Database { 
    private: 
        std::string dataPath;
    public: 
        // Database(const std::string& dataPath); 
        std::string Database::getPassword(); 
        bool Database::updatePassword(const std::string& password = "");
        bool Database::addCredentials(const std::string& platformName, const std::string& userName, const std::string& password);
        bool Database::deleteCredentials(const std::string& platformName);
        std::vector<std::string> Database::getAllPlatforms();
        std::vector<std::string> Database::getCredentials(const std::string& platformName);
        
}; 


#endif // DB_H 