#include "data.h"
#include <fstream>
#include <filesystem>
#include <iostream>

// Define the file paths for data storage
const std::string LOGIN_PASSWORD_FILE = "src/data/loginPassword";
const std::string CREDENTIALS_FILE = "src/data/credentials";

class Data{ 
    private: 
        std::string dataPath;
    public: 
        explicit Data(const std::string& dataPath); 
        bool addData(const std::string& data); 
        bool deleteData(const std::string& data); 
        void showData(const std::string& path = ".") const; 
        std::string getData(const std::string& data); 
};


bool Data::addData(const std::string& data){
    std::ofstream fout(dataPath, std::ios::binary);
    if (!fout) {
        std::cerr << "Error opening file.\n";
        return false;
    }
    fout << data;
    fout.close();
    return true;
}


bool Data::deleteData(const std::string& data){
    if (std::filesystem::exists(dataPath)) {
        std::filesystem::remove(dataPath);
        return true;
    } else {
        std::cerr << "File does not exist.\n";
        return false;
    }
}   

void Data::showData(const std::string& path) const{
    for (const auto& entry : std::filesystem::directory_iterator(path)) {
        std::cout << entry.path() << std::endl;
    }
}

std::string Data::getData(const std::string& data){
    std::ifstream fin(dataPath, std::ios::binary);
    if (!fin) {
        std::cerr << "Error opening file.\n";
        return "";
    }
    std::string content;
    fin >> content;
    fin.close();
    return content;
}