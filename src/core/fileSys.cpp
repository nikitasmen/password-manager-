#include "./fileSys.h"
#include <vector>
#include <filesystem>
#include <string>
#include <fstream>

using namespace std;    
extern string data_path;  // Declare the global variable 


string Database::getPassword(){
    string password; 
    if (std::filesystem::exists(LOGIN_PASSWORD_FILE)) {
        //Read and return the password
        ifstream fin(LOGIN_PASSWORD_FILE, ios::binary);
        getline(fin, password); // Read encrypted value
        fin.close();
    }
    return password; 
}

bool Database::updatePassword(const string& password) {
    ofstream fout(LOGIN_PASSWORD_FILE, ios::binary);
    if (!fout) {
        return false;
    }
    fout << password;
    fout.close();
    return true;
}

bool Database::addCredentials(const string& platformName, const string& userName, const string& password) {
    // Check if platform already exists
    vector<string> platforms = getAllPlatforms();
    for (const string& platform : platforms) {
        if (platform == platformName) {
            return false; // Platform already exists
        }
    }

    // Add new platform credentials
    ofstream fout(CREDENTIALS_FILE, ios::app);
    if (!fout) {
        return false;
    }
    
    fout << platformName << "\n" << userName << "\n" << password << "\n";
    fout.close();
    return true;
}

bool Database::deleteCredentials(const string& platformName) {
    vector<string> platforms = getAllPlatforms();
    vector<string> usernames;
    vector<string> passwords;
    
    ifstream fin(CREDENTIALS_FILE);
    if (!fin) {
        return false;
    }
    
    string platform, username, password;
    while (getline(fin, platform) && getline(fin, username) && getline(fin, password)) {
        if (platform != platformName) {
            platforms.push_back(platform);
            usernames.push_back(username);
            passwords.push_back(password);
        }
    }
    fin.close();
    
    // Write back all credentials except the deleted one
    ofstream fout(CREDENTIALS_FILE);
    if (!fout) {
        return false;
    }
    
    for (size_t i = 0; i < platforms.size(); i++) {
        fout << platforms[i] << "\n" << usernames[i] << "\n" << passwords[i] << "\n";
    }
    fout.close();
    return true;
}

vector<string> Database::getAllPlatforms() {
    vector<string> platforms;
    ifstream fin(CREDENTIALS_FILE);
    if (!fin) {
        return platforms;
    }
    
    string platform, username, password;
    while (getline(fin, platform) && getline(fin, username) && getline(fin, password)) {
        platforms.push_back(platform);
    }
    fin.close();
    return platforms;
}

vector<string> Database::getCredentials(const string& platformName) {
    vector<string> credentials;
    ifstream fin(CREDENTIALS_FILE);
    if (!fin) {
        return credentials;
    }
    
    string platform, username, password;
    while (getline(fin, platform) && getline(fin, username) && getline(fin, password)) {
        if (platform == platformName) {
            credentials.push_back(username);
            credentials.push_back(password);
            break;
        }
    }
    fin.close();
    return credentials;
}