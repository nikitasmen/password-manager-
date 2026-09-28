#ifndef GLOBALCONFIG_H
#define GLOBALCONFIG_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "../vault/Crypto.h"

// Global configuration constants
const int kMaxLoginAttempts = 3;  // Maximum allowed login attempts before exiting

// Encryption algorithm options
// Configuration structure for file-based settings
struct AppConfig {
    // Application version
    std::string version = "v1.7.0";

    // Core settings
    std::string dataPath = "./data";
    CipherAlg defaultCipher = CipherAlg::Aes256Gcm;          // for new entries (docs/PROTOCOL.md §2)
    int maxLoginAttempts = 3;

    // Clipboard settings
    int clipboardTimeoutSeconds = 30;
    bool autoClipboardClear = true;

    // Security settings
    bool requirePasswordConfirmation = true;
    int minPasswordLength = 8;

    // UI settings
    bool showEncryptionInCredentials = true;
    std::string defaultUIMode = "auto";  // "cli", "gui", or "auto"

    // ESP32 vault store; empty espHost = local only (no sync)
    std::string espHost;
    int espPort = 443;
    std::string espCert = "esp32/vault/cert.pem";  // pinned server cert
    std::string espClientCert;                     // this device's cert + key: esp32/pki.sh add <name>
    std::string espClientKey;

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
    [[nodiscard]] const AppConfig& getConfig() const {
        return config_;
    }

    // Update configuration
    void updateConfig(const AppConfig& newConfig);

    // Get specific config values
    [[nodiscard]] const std::string& getVersion() const {
        return config_.version;
    }
    [[nodiscard]] const std::string& getDataPath() const {
        return config_.dataPath;
    }
    [[nodiscard]] bool isAutoClipboardClearEnabled() const {
        return config_.autoClipboardClear;
    }
    [[nodiscard]] int getMaxLoginAttempts() const {
        return config_.maxLoginAttempts;
    }
    [[nodiscard]] int getClipboardTimeoutSeconds() const {
        return config_.clipboardTimeoutSeconds;
    }
    [[nodiscard]] bool getAutoClipboardClear() const {
        return config_.autoClipboardClear;
    }
    [[nodiscard]] bool getRequirePasswordConfirmation() const {
        return config_.requirePasswordConfirmation;
    }
    [[nodiscard]] int getMinPasswordLength() const {
        return config_.minPasswordLength;
    }
    [[nodiscard]] bool getShowEncryptionInCredentials() const {
        return config_.showEncryptionInCredentials;
    }
    [[nodiscard]] const std::string& getDefaultUIMode() const {
        return config_.defaultUIMode;
    }

    // Update/Repository settings
    [[nodiscard]] const std::string& getGithubOwner() const {
        return config_.githubOwner;
    }
    [[nodiscard]] const std::string& getGithubRepo() const {
        return config_.githubRepo;
    }
    [[nodiscard]] bool getAutoCheckUpdates() const {
        return config_.autoCheckUpdates;
    }
    [[nodiscard]] int getUpdateCheckIntervalDays() const {
        return config_.updateCheckIntervalDays;
    }

    // Set specific config values
    void setVersion(const std::string& version);
    void setDataPath(const std::string& path);
    void setMaxLoginAttempts(int attempts);
    void setClipboardTimeoutSeconds(int seconds);
    void setAutoClipboardClear(bool enabled);
    void setRequirePasswordConfirmation(bool required);
    void setMinPasswordLength(int length);
    void setShowEncryptionInCredentials(bool show);
    void setDefaultUIMode(const std::string& mode);

    // Update/Repository settings
    void setGithubOwner(const std::string& owner);
    void setGithubRepo(const std::string& repo);
    void setAutoCheckUpdates(bool enabled);
    void setUpdateCheckIntervalDays(int days);

   private:
    ConfigManager() = default;
    AppConfig config_;
};


#endif  // GLOBALCONFIG_H
