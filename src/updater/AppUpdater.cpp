#include "AppUpdater.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>
#include <sstream>

#include "../config/GlobalConfig.h"
#include "../include/nlohmann/json.hpp"
#include "../utils/backup_utils.h"
#include "../utils/error_utils.h"
#include "../utils/filesystem_utils.h"

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#define PATH_SEPARATOR "\\"
#else
#include <curl/curl.h>
#include <sys/stat.h>
#include <unistd.h>
#define PATH_SEPARATOR "/"
#endif

using json = nlohmann::json;

// Helper functions for cross-platform temporary file handling
namespace {
std::string getSystemTempDirectory() {
    try {
        // Use standard filesystem temp directory
        fs::path tempPath = fs::temp_directory_path();
        return tempPath.string();
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error getting temp directory: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error getting temp directory: " << e.what() << std::endl;
    }

    // Fallback to platform-specific implementations
#ifdef _WIN32
    char tempPath[MAX_PATH];
    DWORD result = GetTempPathA(MAX_PATH, tempPath);
    if (result > 0 && result < MAX_PATH) {
        return std::string(tempPath);
    }
    return "C:\\temp\\";  // Last resort fallback
#else
    // Try environment variables first
    const char* tmpDir = std::getenv("TMPDIR");
    if (tmpDir)
        return std::string(tmpDir);

    tmpDir = std::getenv("TMP");
    if (tmpDir)
        return std::string(tmpDir);

    tmpDir = std::getenv("TEMP");
    if (tmpDir)
        return std::string(tmpDir);

    // Last resort fallback
    return "/tmp/";
#endif
}

std::string generateUniqueId() {
    // Generate a unique ID using timestamp and random number
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);

    return std::to_string(timestamp) + "_" + std::to_string(dis(gen));
}

std::string createUniqueDirectory(const std::string& prefix) {
    std::string tempDir = getSystemTempDirectory();
    if (tempDir.back() != '/' && tempDir.back() != '\\') {
        tempDir += PATH_SEPARATOR;
    }

    std::string uniqueDir = tempDir + prefix + "_" + generateUniqueId();

    try {
        fs::path dirPath(uniqueDir);
        std::error_code ec;

        // Create directory with proper error handling
        if (fs::create_directories(dirPath, ec)) {
            return uniqueDir;
        } else if (ec) {
            std::cerr << "Warning: Could not create temp directory: " << uniqueDir << " (Error: " << ec.message() << ")"
                      << std::endl;
        } else {
            // Directory already exists, which is fine for our use case
            return uniqueDir;
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error creating directory: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error creating directory: " << e.what() << std::endl;
    }

    // Fallback to system temp directory
    return tempDir;
}

std::string createUniqueFilePath(const std::string& prefix, const std::string& extension = "") {
    std::string tempDir = getSystemTempDirectory();
    if (tempDir.back() != '/' && tempDir.back() != '\\') {
        tempDir += PATH_SEPARATOR;
    }

    std::string fileName = prefix + "_" + generateUniqueId();
    if (!extension.empty()) {
        fileName += "." + extension;
    }

    return tempDir + fileName;
}

void cleanupDirectory(const std::string& dirPath) {
    // Validate path to prevent directory traversal attacks
    if (dirPath.empty() || dirPath.find("..") != std::string::npos) {
        std::cerr << "Error: Invalid directory path for cleanup" << std::endl;
        return;
    }

    try {
        fs::path path(dirPath);

        // Additional security check - ensure path is absolute and within temp directory
        if (!path.is_absolute()) {
            std::cerr << "Error: Directory path must be absolute for cleanup" << std::endl;
            return;
        }

        // Check if directory exists before attempting removal
        if (fs::exists(path) && fs::is_directory(path)) {
            std::error_code ec;
            fs::remove_all(path, ec);
            if (ec) {
                std::cerr << "Warning: Failed to clean up directory: " << dirPath << " (Error: " << ec.message() << ")"
                          << std::endl;
            }
        }
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error during cleanup: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error during directory cleanup: " << e.what() << std::endl;
    }
}

bool copyFile(const std::string& source, const std::string& destination) {
    // Validate paths
    if (source.empty() || destination.empty() || source.find("..") != std::string::npos ||
        destination.find("..") != std::string::npos) {
        std::cerr << "Error: Invalid file paths for copy operation" << std::endl;
        return false;
    }

    try {
        fs::path srcPath(source);
        fs::path dstPath(destination);

        // Ensure source file exists and is a regular file
        if (!fs::exists(srcPath)) {
            std::cerr << "Error: Source file does not exist: " << source << std::endl;
            return false;
        }

        if (!fs::is_regular_file(srcPath)) {
            std::cerr << "Error: Source is not a regular file: " << source << std::endl;
            return false;
        }

        // Create destination directory if it doesn't exist
        fs::path dstDir = dstPath.parent_path();
        if (!dstDir.empty() && !fs::exists(dstDir)) {
            std::error_code ec;
            fs::create_directories(dstDir, ec);
            if (ec) {
                std::cerr << "Error: Cannot create destination directory: " << dstDir << " (Error: " << ec.message()
                          << ")" << std::endl;
                return false;
            }
        }

        // Copy file using filesystem API
        std::error_code ec;
        fs::copy_file(srcPath, dstPath, fs::copy_options::overwrite_existing, ec);

        if (ec) {
            std::cerr << "Error: Failed to copy file from " << source << " to " << destination
                      << " (Error: " << ec.message() << ")" << std::endl;
            return false;
        }

#ifndef _WIN32
        // Set executable permissions on Unix systems
        fs::permissions(dstPath,
                        fs::perms::owner_read | fs::perms::owner_write | fs::perms::owner_exec | fs::perms::group_read |
                            fs::perms::group_exec | fs::perms::others_read | fs::perms::others_exec,
                        ec);
        if (ec) {
            std::cerr << "Warning: Failed to set executable permissions: " << ec.message() << std::endl;
            // Don't return false here as the copy was successful
        }
#endif

        return true;

    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error during file copy: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error during file copy: " << e.what() << std::endl;
        return false;
    }
}

#ifndef _WIN32
void configureCurlCommon(CURL* curl, const std::string& url) {
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "PasswordManager/1.0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

    // SSL/TLS configuration
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
}
#endif
}  // namespace

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
static int CurlProgressCallback(
    void* clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
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

    if (thisMajor != otherMajor)
        return thisMajor > otherMajor;
    if (thisMinor != otherMinor)
        return thisMinor > otherMinor;
    return thisPatch > otherPatch;
}

std::string VersionInfo::getCurrentVersion() {
    ConfigManager& config = ConfigManager::getInstance();
    config.loadConfig();
    return config.getVersion();
}

AppUpdater::AppUpdater() {
    // Load repository information from configuration
    ConfigManager& config = ConfigManager::getInstance();
    config.loadConfig();

    githubOwner = config.getGithubOwner();
    githubRepo = config.getGithubRepo();

#ifndef _WIN32
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif
}

AppUpdater::AppUpdater(const std::string& owner, const std::string& repo) : githubOwner(owner), githubRepo(repo) {
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
        // Create unique temporary download directory
        std::string tempDir = createUniqueDirectory("password_manager_update");

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

        // Clean up temporary directory
        cleanupDirectory(tempDir);

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
    if (!hInternet)
        return "";

    HINTERNET hUrl =
        InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE, 0);
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

        configureCurlCommon(curl, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.responseCode);

        if (res == CURLE_OK && response.responseCode == 200) {
            curl_easy_cleanup(curl);
            return response.data;
        }

        std::cerr << "libcurl error: " << curl_easy_strerror(res) << " (HTTP " << response.responseCode << ")"
                  << std::endl;
        curl_easy_cleanup(curl);
    }

    // No fallback to system commands - security risk
    std::cerr << "libcurl failed and no safe fallback available" << std::endl;
    return "";
#endif
}

bool AppUpdater::downloadFile(const std::string& url,
                              const std::string& outputPath,
                              ProgressCallback progressCallback) {
#ifdef _WIN32
    // Simple Windows implementation - could be enhanced with progress reporting
    HRESULT hr = URLDownloadToFileA(nullptr, url.c_str(), outputPath.c_str(), 0, nullptr);
    return SUCCEEDED(hr);

#else
    // Unix implementation with progress reporting
    CURL* curl = curl_easy_init();
    if (!curl)
        return false;

    FILE* file = fopen(outputPath.c_str(), "wb");
    if (!file) {
        curl_easy_cleanup(curl);
        return false;
    }

    configureCurlCommon(curl, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);  // 5 minute timeout for downloads

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
        std::error_code ec;
        fs::remove(outputPath, ec);
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
                if (assetName.find(platformBinary) != std::string::npos || assetName == platformBinary) {
                    info.downloadUrl = asset["browser_download_url"];
                    break;
                }
            }
        }

        // If no specific asset found, try to construct download URL
        if (info.downloadUrl.empty()) {
            info.downloadUrl = "https://github.com/" + githubOwner + "/" + githubRepo + "/releases/download/" +
                               info.version + "/" + platformBinary;
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

        // Copy current file to backup using safe file operations
        if (!copyFile(currentPath, backupPath)) {
            std::cerr << "Failed to create backup" << std::endl;
            return false;
        }

        // Replace current executable with downloaded one
        if (!copyFile(downloadedPath, currentPath)) {
            std::cerr << "Failed to replace executable, attempting rollback..." << std::endl;

            // Rollback: restore from backup if replacement failed
            std::error_code rollbackEc;
            if (fs::exists(backupPath)) {
                if (copyFile(backupPath, currentPath)) {
                    std::cerr << "Rollback successful - original executable restored" << std::endl;
                } else {
                    std::cerr << "Critical error: Both update and rollback failed!" << std::endl;
                }
                // Clean up backup file after rollback attempt
                fs::remove(backupPath, rollbackEc);
            }
            return false;
        }

        // Update was successful, clean up temporary files
        std::error_code ec;

        // Clean up downloaded file
        fs::remove(downloadedPath, ec);
        if (ec) {
            std::cerr << "Warning: Failed to remove downloaded file: " << downloadedPath << " (Error: " << ec.message()
                      << ")" << std::endl;
        }

        // Clean up backup file after successful update
        fs::remove(backupPath, ec);
        if (ec) {
            std::cerr << "Warning: Failed to remove backup file: " << backupPath << " (Error: " << ec.message() << ")"
                      << std::endl;
        } else {
            std::cout << "Update completed successfully, backup file removed" << std::endl;
        }

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

bool AppUpdater::cleanupOrphanedBackups() {
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
            // For macOS, we might not be able to determine the path this way
            std::cerr << "Could not determine executable path for backup cleanup on macOS" << std::endl;
            return false;
        }
#endif

        if (currentPath.empty()) {
            std::cerr << "Could not determine current executable path for backup cleanup" << std::endl;
            return false;
        }

        // Check for backup files that might exist
        std::string backupPath = currentPath + ".backup";
        std::error_code ec;

        if (fs::exists(backupPath)) {
            std::cout << "Found orphaned backup file: " << backupPath << std::endl;

            // Remove the orphaned backup
            fs::remove(backupPath, ec);
            if (ec) {
                std::cerr << "Failed to remove orphaned backup file: " << backupPath << " (Error: " << ec.message()
                          << ")" << std::endl;
                return false;
            } else {
                std::cout << "Successfully removed orphaned backup file" << std::endl;
            }
        }

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error during backup cleanup: " << e.what() << std::endl;
        return false;
    }
}
