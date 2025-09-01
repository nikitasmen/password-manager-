#ifndef GLOBALCONFIG_H
#define GLOBALCONFIG_H

#include <map>
#include <string>
#include <vector>

// Global configuration constants
const int MAX_LOGIN_ATTEMPTS = 3;  // Maximum allowed login attempts before exiting

// Encryption algorithm options
enum class EncryptionType {
    LFSR = 0,  // Linear Feedback Shift Register (basic)
    AES = 1,   // Advanced Encryption Standard (stronger)
    RSA = 2,   // RSA (asymmetric, used for credential encryption via hybrid encryption)
    // Keep this as the last entry to track count
    COUNT
};

// Configuration structure for file-based settings
struct AppConfig {
    // Application version
    std::string version = "v1.7.0";

    // Core settings
    std::string dataPath = "./data";
    EncryptionType defaultEncryption = EncryptionType::AES;
    int maxLoginAttempts = 3;

    // Clipboard settings
    int clipboardTimeoutSeconds = 30;
    bool autoClipboardClear = true;

    // Security settings
    bool requirePasswordConfirmation = true;
    int minPasswordLength = 8;

    // LFSR settings
    std::vector<int> lfsrTaps = {0, 2};
    std::vector<int> lfsrInitState = {1, 0, 1};

    // UI settings
    bool showEncryptionInCredentials = true;
    std::string defaultUIMode = "auto";  // "cli", "gui", or "auto"

    // Update/Repository settings
    std::string githubOwner = "nikitasmen";
    std::string githubRepo = "password-manager-";
    bool autoCheckUpdates = false;
    int updateCheckIntervalDays = 7;
};

// Configuration manager class
class ConfigManager {
   public:
    static ConfigManager& getInstance();

    // Load configuration from file
    bool loadConfig(const std::string& configPath = ".config");

    // Save configuration to file
    bool saveConfig(const std::string& configPath = ".config");

    // Get current configuration
    const AppConfig& getConfig() const {
        return config_;
    }

    // Update configuration
    void updateConfig(const AppConfig& newConfig);

    // Get specific config values
    const std::string& getVersion() const {
        return config_.version;
    }
    const std::string& getDataPath() const {
        return config_.dataPath;
    }
    EncryptionType getDefaultEncryption() const {
        return config_.defaultEncryption;
    }
    bool isAutoClipboardClearEnabled() const {
        return config_.autoClipboardClear;
    }
    int getMaxLoginAttempts() const {
        return config_.maxLoginAttempts;
    }
    int getClipboardTimeoutSeconds() const {
        return config_.clipboardTimeoutSeconds;
    }
    bool getAutoClipboardClear() const {
        return config_.autoClipboardClear;
    }
    bool getRequirePasswordConfirmation() const {
        return config_.requirePasswordConfirmation;
    }
    int getMinPasswordLength() const {
        return config_.minPasswordLength;
    }
    bool getShowEncryptionInCredentials() const {
        return config_.showEncryptionInCredentials;
    }
    const std::string& getDefaultUIMode() const {
        return config_.defaultUIMode;
    }
    const std::vector<int>& getLfsrTaps() const {
        return config_.lfsrTaps;
    }
    const std::vector<int>& getLfsrInitState() const {
        return config_.lfsrInitState;
    }

    // Update/Repository settings
    const std::string& getGithubOwner() const {
        return config_.githubOwner;
    }
    const std::string& getGithubRepo() const {
        return config_.githubRepo;
    }
    bool getAutoCheckUpdates() const {
        return config_.autoCheckUpdates;
    }
    int getUpdateCheckIntervalDays() const {
        return config_.updateCheckIntervalDays;
    }

    // Set specific config values
    void setVersion(const std::string& version);
    void setDataPath(const std::string& path);
    // Set default encryption and migrate master password if needed
    // Deprecated: Use the new method that accepts LFSR settings
    void setDefaultEncryption(EncryptionType newType, const std::string& masterPassword);

    // New method for handling encryption change with LFSR settings
    void setDefaultEncryption(EncryptionType newType,
                              const std::string& masterPassword,
                              const std::vector<int>& newLfsrTaps,
                              const std::vector<int>& newLfsrInitState);
    void setMaxLoginAttempts(int attempts);
    void setClipboardTimeoutSeconds(int seconds);
    void setAutoClipboardClear(bool enabled);
    void setRequirePasswordConfirmation(bool required);
    void setMinPasswordLength(int length);
    void setShowEncryptionInCredentials(bool show);
    void setDefaultUIMode(const std::string& mode);
    void setLfsrTaps(const std::vector<int>& newTaps);
    void setLfsrInitState(const std::vector<int>& newInitState);
    bool updateLfsrSettings(const std::vector<int>& newTaps,
                            const std::vector<int>& newInitState,
                            const std::string& masterPassword);

    // Update/Repository settings
    void setGithubOwner(const std::string& owner);
    void setGithubRepo(const std::string& repo);
    void setAutoCheckUpdates(bool enabled);
    void setUpdateCheckIntervalDays(int days);

   private:
    ConfigManager() = default;
    AppConfig config_;

    // Helper methods for parsing
    static EncryptionType parseEncryptionType(const std::string& value);
    static std::string encryptionTypeToString(EncryptionType type);
    static std::vector<int> parseIntArray(const std::string& value);
    static std::string intArrayToString(const std::vector<int>& array);
};

// Helper functions for encryption type management
namespace EncryptionUtils {
// Get human-readable name for an encryption type
const char* getDisplayName(EncryptionType type);

// Get all available encryption types
std::vector<EncryptionType> getAllTypes();

// Convert dropdown index to encryption type
EncryptionType fromDropdownIndex(int index);

// Convert encryption type to dropdown index
int toDropdownIndex(EncryptionType type);

// Get default encryption type
EncryptionType getDefault();

// Get encryption type mapping for menu choices
const std::map<int, EncryptionType>& getChoiceMapping();
}  // namespace EncryptionUtils

#endif  // GLOBALCONFIG_H
