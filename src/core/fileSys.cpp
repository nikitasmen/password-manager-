#include "../data/loginPassword"
#include "../data/credentials"
#include <fstream>  
#include <iostream>
#include <filesystem>
#include <string>
#include <vector>


extern std::string data_path;  // Declare the global variable


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
