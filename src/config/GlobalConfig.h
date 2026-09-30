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
    std::string version = "v2.0.0";

    // Core settings
    std::string dataPath;  // empty = ConfigManager::dataDir()
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
    bool localCopy = true;  // false = device-only: the ESP32 is the only store, nothing kept on this machine
    int espPort = 443;
    // Relative paths resolve against configDir(); `esp32/pki.sh pair <name>` puts these files there.
    std::string espCert = "server.pem";        // the board's pinned server cert
    std::string espClientCert = "device.pem";  // this device's certificate
    std::string espClientKey = "device.key";   // ...and its private key

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

    // One location for every client (GUI, TUI, clients/python), independent of the working directory (XDG):
    static std::string configDir();   // $XDG_CONFIG_HOME/pwvault, default ~/.config/pwvault
    static std::string configFile();  // configDir()/config
    static std::string dataDir();     // $XDG_DATA_HOME/pwvault, default ~/.local/share/pwvault

    // Load configuration from file (creates it with defaults if missing); resolves paths to absolute
    bool loadConfig(const std::string& configPath = configFile());

    // Save configuration to file (owner-only)
    bool saveConfig(const std::string& configPath = configFile());

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

    // Set specific config values
    void setVersion(const std::string& version);

   private:
    ConfigManager() = default;
    void resolvePaths();
    AppConfig config_;
    std::string configFile_;  // the file loadConfig() read; relative paths in it resolve against its folder
};


#endif  // GLOBALCONFIG_H
