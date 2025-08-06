#include "AppUpdater.h"
#include "../config/GlobalConfig.h"
#include "../include/nlohmann/json.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <cstdlib>

#ifdef _WIN32
    #include <windows.h>
    #include <wininet.h>
    #include <direct.h>
    #pragma comment(lib, "wininet.lib")
    #define PATH_SEPARATOR "\\"
#else
    #include <curl/curl.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #define PATH_SEPARATOR "/"
#endif

using json = nlohmann::json;

// Helper struct for HTTP response
struct HttpResponse {
    std::string data;
    long responseCode = 0;
};

// Callback for libcurl to write response data
#ifndef _WIN32
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, HttpResponse* response) {
    size_t totalSize = size * nmemb;
    response->data.append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

// Callback for libcurl to report download progress
static int CurlProgressCallback(void* clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    auto* progressCallback = static_cast<AppUpdater::ProgressCallback*>(clientp);
    if (progressCallback && dltotal > 0) {
        int percentage = static_cast<int>((dlnow * 100) / dltotal);
        (*progressCallback)(percentage, "Downloading...");
    }
    return 0;
}
#endif

bool VersionInfo::isNewerThan(const std::string& other) const {
    // Enhanced version comparison - handles v1.2.3, v1.2, and v1 formats
    auto parseVersion = [](const std::string& v) -> std::tuple<int, int, int> {
        std::string cleanVersion = v;
        if (cleanVersion.length() > 0 && cleanVersion[0] == 'v') {
            cleanVersion = cleanVersion.substr(1);
        }
        
        // First try full semantic versioning (v1.2.3)
        std::regex fullVersionRegex(R"((\d+)\.(\d+)\.(\d+))");
        std::smatch match;
        if (std::regex_match(cleanVersion, match, fullVersionRegex)) {
            return {std::stoi(match[1]), std::stoi(match[2]), std::stoi(match[3])};
        }
        
        // Try two-part versioning (v1.2)
        std::regex shortVersionRegex(R"((\d+)\.(\d+))");
        if (std::regex_match(cleanVersion, match, shortVersionRegex)) {
            return {std::stoi(match[1]), std::stoi(match[2]), 0};
        }
        
        // Try single number (v1)
        std::regex singleVersionRegex(R"((\d+))");
        if (std::regex_match(cleanVersion, match, singleVersionRegex)) {
            return {std::stoi(match[1]), 0, 0};
        }
        
        return {0, 0, 0};
    };
    
    auto [thisMajor, thisMinor, thisPatch] = parseVersion(version);
    auto [otherMajor, otherMinor, otherPatch] = parseVersion(other);
    
    if (thisMajor != otherMajor) return thisMajor > otherMajor;
    if (thisMinor != otherMinor) return thisMinor > otherMinor;
    return thisPatch > otherPatch;
}

std::string VersionInfo::getCurrentVersion() {
    ConfigManager& config = ConfigManager::getInstance();
    config.loadConfig();
    return config.getVersion();
}

AppUpdater::AppUpdater(const std::string& owner, const std::string& repo)
    : githubOwner(owner), githubRepo(repo) {
#ifndef _WIN32
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif
}

void AppUpdater::checkForUpdates(std::function<void(bool, const std::string&, const VersionInfo&)> callback) {
    try {
        std::string apiUrl = "https://api.github.com/repos/" + githubOwner + "/" + githubRepo + "/releases/latest";
        std::string response = makeHttpRequest(apiUrl);
        
        if (response.empty()) {
            callback(false, "Failed to connect to GitHub API", VersionInfo{});
            return;
        }
        
        VersionInfo latestVersion = parseReleaseInfo(response);
        if (latestVersion.version.empty()) {
            callback(false, "Failed to parse version information", VersionInfo{});
            return;
        }
        
        std::string currentVersion = VersionInfo::getCurrentVersion();
        if (latestVersion.isNewerThan(currentVersion)) {
            callback(true, "Update available: " + latestVersion.version, latestVersion);
        } else {
            callback(true, "You are running the latest version", latestVersion);
        }
        
    } catch (const std::exception& e) {
        callback(false, "Error checking for updates: " + std::string(e.what()), VersionInfo{});
    }
}

void AppUpdater::downloadUpdate(const VersionInfo& versionInfo, 
                               ProgressCallback progressCallback,
                               CompletionCallback completionCallback) {
    try {
        // Create temporary download directory using basic C functions
        std::string tempDir = "/tmp/password_manager_update";
        #ifdef _WIN32
        _mkdir(tempDir.c_str());
        #else
        mkdir(tempDir.c_str(), 0755);
        #endif
        
        // Determine download filename
        std::string filename = getPlatformBinaryName();
        std::string downloadPath = tempDir + PATH_SEPARATOR + filename;
        
        progressCallback(0, "Starting download...");
        
        bool success = downloadFile(versionInfo.downloadUrl, downloadPath, progressCallback);
        
        if (success) {
            progressCallback(100, "Download complete. Installing...");
            
            if (installUpdate(downloadPath)) {
                // Update version in config file
                updateVersionInConfig(versionInfo.version);
                completionCallback(true, "Update installed successfully! Please restart the application.");
            } else {
                completionCallback(false, "Failed to install update. Please install manually.");
            }
        } else {
            completionCallback(false, "Failed to download update.");
        }
        
    } catch (const std::exception& e) {
        completionCallback(false, "Error during update: " + std::string(e.what()));
    }
}

std::string AppUpdater::getPlatformBinaryName() {
#ifdef _WIN32
    return "password_manager_gui.exe";
#elif defined(__APPLE__)
    return "password_manager_gui";
#elif defined(__linux__)
    return "password_manager_gui";
#else
    return "password_manager_gui";
#endif
}

std::string AppUpdater::makeHttpRequest(const std::string& url) {
#ifdef _WIN32
    // Windows implementation using WinINet
    HINTERNET hInternet = InternetOpenA("PasswordManager/1.0", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (!hInternet) return "";
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return "";
    }
    
    std::string response;
    char buffer[4096];
    DWORD bytesRead;
    
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        response.append(buffer, bytesRead);
    }
    
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    return response;
    
#else
    // First try libcurl if available
    CURL* curl = curl_easy_init();
    if (curl) {
        HttpResponse response;
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "PasswordManager/1.0");
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
        
        // SSL/TLS configuration
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        
        CURLcode res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.responseCode);
        
        if (res == CURLE_OK && response.responseCode == 200) {
            curl_easy_cleanup(curl);
            return response.data;
        }
        
        std::cerr << "libcurl error: " << curl_easy_strerror(res) << " (HTTP " << response.responseCode << ")" << std::endl;
        curl_easy_cleanup(curl);
    }
    
    // Fallback to system curl command
    std::cout << "Falling back to system curl command..." << std::endl;
    
    // Create a temporary file for the response
    std::string tempFile = "/tmp/pm_http_response.tmp";
    
    // Build curl command
    std::string command = "curl -s -L -A \"PasswordManager/1.0\" --connect-timeout 10 --max-time 30 \"" + url + "\" -o \"" + tempFile + "\"";
    
    // Execute curl command
    int result = system(command.c_str());
    
    if (result == 0) {
        // Read the response from temp file
        std::ifstream responseFile(tempFile);
        if (responseFile.is_open()) {
            std::string response((std::istreambuf_iterator<char>(responseFile)),
                               std::istreambuf_iterator<char>());
            responseFile.close();
            remove(tempFile.c_str()); // Clean up temp file
            return response;
        }
    }
    
    // Clean up temp file in case of error
    remove(tempFile.c_str());
    
    std::cerr << "Both libcurl and system curl failed" << std::endl;
    return "";
#endif
}

bool AppUpdater::downloadFile(const std::string& url, const std::string& outputPath, ProgressCallback progressCallback) {
#ifdef _WIN32
    // Simple Windows implementation - could be enhanced with progress reporting
    HRESULT hr = URLDownloadToFileA(nullptr, url.c_str(), outputPath.c_str(), 0, nullptr);
    return SUCCEEDED(hr);
    
#else
    // Unix implementation with progress reporting
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    
    FILE* file = fopen(outputPath.c_str(), "wb");
    if (!file) {
        curl_easy_cleanup(curl);
        return false;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "PasswordManager/1.0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L); // 5 minute timeout
    
    // Progress reporting
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, CurlProgressCallback);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &progressCallback);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    
    CURLcode res = curl_easy_perform(curl);
    long responseCode;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
    
    curl_easy_cleanup(curl);
    fclose(file);
    
    if (res != CURLE_OK || responseCode != 200) {
        remove(outputPath.c_str());
        return false;
    }
    
    return true;
#endif
}

VersionInfo AppUpdater::parseReleaseInfo(const std::string& jsonResponse) {
    try {
        json releaseData = json::parse(jsonResponse);
        
        VersionInfo info;
        info.version = releaseData["tag_name"];
        info.releaseNotes = releaseData.value("body", "");
        info.isPrerelease = releaseData.value("prerelease", false);
        
        // Find the appropriate asset for our platform
        std::string platformBinary = getPlatformBinaryName();
        
        if (releaseData.contains("assets") && releaseData["assets"].is_array()) {
            for (const auto& asset : releaseData["assets"]) {
                std::string assetName = asset["name"];
                if (assetName.find(platformBinary) != std::string::npos || 
                    assetName == platformBinary) {
                    info.downloadUrl = asset["browser_download_url"];
                    break;
                }
            }
        }
        
        // If no specific asset found, try to construct download URL
        if (info.downloadUrl.empty()) {
            info.downloadUrl = "https://github.com/" + githubOwner + "/" + githubRepo + 
                             "/releases/download/" + info.version + "/" + platformBinary;
        }
        
        return info;
        
    } catch (const std::exception& e) {
        std::cerr << "Error parsing GitHub release info: " << e.what() << std::endl;
        return VersionInfo{};
    }
}

bool AppUpdater::installUpdate(const std::string& downloadedPath) {
    try {
        // Get current executable path
        std::string currentPath;
        
#ifdef _WIN32
        char buffer[MAX_PATH];
        GetModuleFileNameA(nullptr, buffer, MAX_PATH);
        currentPath = buffer;
#else
        char buffer[1024];
        ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
        if (len != -1) {
            buffer[len] = '\0';
            currentPath = buffer;
        } else {
            // Fallback for macOS - try to get from argv[0] or environment
            std::cerr << "Could not determine executable path on macOS" << std::endl;
            return false;
        }
#endif
        
        if (currentPath.empty()) {
            std::cerr << "Could not determine current executable path" << std::endl;
            return false;
        }
        
        // Create backup of current executable
        std::string backupPath = currentPath + ".backup";
        
        // Copy current file to backup using system commands
        std::string copyCommand = "cp \"" + currentPath + "\" \"" + backupPath + "\"";
        if (system(copyCommand.c_str()) != 0) {
            std::cerr << "Failed to create backup" << std::endl;
            return false;
        }
        
        // Replace current executable with downloaded one
        std::string replaceCommand = "cp \"" + downloadedPath + "\" \"" + currentPath + "\"";
        if (system(replaceCommand.c_str()) != 0) {
            std::cerr << "Failed to replace executable" << std::endl;
            return false;
        }
        
        // Make executable on Unix systems
#ifndef _WIN32
        chmod(currentPath.c_str(), 0755);
#endif
        
        // Clean up downloaded file
        remove(downloadedPath.c_str());
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error installing update: " << e.what() << std::endl;
        return false;
    }
}

void AppUpdater::updateVersionInConfig(const std::string& newVersion) {
    ConfigManager& config = ConfigManager::getInstance();
    config.setVersion(newVersion);
}
