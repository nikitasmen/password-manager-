#ifndef DATA_H
#define DATA_H 

#include <filesystem> 
#include <fstream> 
#include <iostream> 

class Data{
    private: 
        std::string dataPath;
    public: 
        Data(const std::string& dataPath); 
        bool addData(const std::string& data); 
        bool deleteData(const std::string& data); 
        void showData(const std::string& path = ".") const; 
        std::string getData(const std::string& data); 
}; 

#endif