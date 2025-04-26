#include "../data/loginPassword"
#include "../data/credentials"
#include "./fileSys.h"
#include <vector>
#include <filesystem>
#include <string>

using namespace std;    
extern string data_path;  // Declare the global variable


class Database { 
    private: 
        string dataPath;

    public: 
        // Database(const  string& dataPath); 
        string Database::getPassword(); 
        bool Database::updatePassword(const  string& password = "");
        bool Database::addCredentials(const  string& platformName, const  string& userName, const  string& password);
        bool Database::deleteCredentials(const  string& platformName);
        vector<string> Database::getAllPlatforms();
        vector<string> Database::getCredentials(const  string& platformName);
        
}; 


 string Database::getPassword(){
     string password; 
     string loginFile = "enter"; // Simplified for single command usage
    if ( filesystem::exists(loginFile)) {
         //Read and return the password
        ifstream fin(loginFile, ios::binary);
        getline(fin, password); // Read encrypted value
        fin.close();
    }
    return 0; 
}