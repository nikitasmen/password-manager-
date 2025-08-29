#ifndef APP_UPDATER_H
#define APP_UPDATER_H

#include <functional>
#include <memory>
#include <string>

/**
 * @struct VersionInfo
 * @brief Holds version information from GitHub API
 */
struct VersionInfo {
    std::string version;       // e.g., "v1.2.3"
    std::string downloadUrl;   // URL to download the binary
    std::string releaseNotes;  // Release notes
    bool isPrerelease = false;

    /**
     * @brief Compare two version strings
     * @param other Other version to compare with
     * @return true if this version is newer than other
     */
    bool isNewerThan(const std::string& other) const;

    /**
     * @brief Get current application version
     * @return Current version string
     */
    static std::string getCurrentVersion();
};

/**
 * @class AppUpdater
 * @brief Handles checking for and downloading application updates from GitHub
 */
class AppUpdater {
   public:
    using ProgressCallback = std::function<void(int percentage, const std::string& status)>;
    using CompletionCallback = std::function<void(bool success, const std::string& message)>;

    /**
     * @brief Default constructor using configuration system
     * Gets GitHub repository information from config file
     */
    AppUpdater();

    /**
     * @brief Constructor with explicit repository information
     * @param owner GitHub repository owner (e.g., "username")
     * @param repo GitHub repository name (e.g., "password-manager")
     * @deprecated Use default constructor instead for configuration-based setup
     */
    AppUpdater(const std::string& owner, const std::string& repo);

    /**
     * @brief Check for updates from GitHub releases
     * @param callback Callback with success status and version info or error message
     */
    void checkForUpdates(
        std::function<void(bool success, const std::string& message, const VersionInfo& versionInfo)> callback);

    /**
     * @brief Download and install the latest version
     * @param versionInfo Version information from checkForUpdates
     * @param progressCallback Called during download to report progress
     * @param completionCallback Called when download completes
     */
    void downloadUpdate(const VersionInfo& versionInfo,
                        ProgressCallback progressCallback,
                        CompletionCallback completionCallback);

    /**
     * @brief Get the platform-specific binary name
     * @return Platform-specific executable name
     */
    static std::string getPlatformBinaryName();

    /**
     * @brief Clean up orphaned backup files from previous failed updates
     * @return true if cleanup was successful or no files to clean
     */
    static bool cleanupOrphanedBackups();

   private:
    std::string githubOwner;
    std::string githubRepo;

    /**
     * @brief Make HTTP request to GitHub API
     * @param url API endpoint URL
     * @return Response body or empty string on failure
     */
    std::string makeHttpRequest(const std::string& url);

    /**
     * @brief Download file from URL with progress reporting
     * @param url Download URL
     * @param outputPath Local file path to save
     * @param progressCallback Progress reporting callback
     * @return true if download succeeded
     */
    bool downloadFile(const std::string& url, const std::string& outputPath, ProgressCallback progressCallback);

    /**
     * @brief Parse GitHub releases API response
     * @param jsonResponse JSON response from GitHub API
     * @return VersionInfo for latest compatible release
     */
    VersionInfo parseReleaseInfo(const std::string& jsonResponse);

    /**
     * @brief Install downloaded update
     * @param downloadedPath Path to downloaded file
     * @return true if installation succeeded
     */
    bool installUpdate(const std::string& downloadedPath);

    /**
     * @brief Update version in configuration file
     * @param newVersion New version to set
     */
    void updateVersionInConfig(const std::string& newVersion);
};

#endif  // APP_UPDATER_H
