#include "GlobalConfig.h"

#include <cstdlib>
#include <filesystem>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <vector>


// ConfigManager implementation
ConfigManager& ConfigManager::getInstance() {
    static ConfigManager instance;
    return instance;
}

namespace {
std::string home() {
    const char* h = std::getenv("HOME");
    return h && *h ? h : ".";
}

std::string xdgDir(const char* var, const char* fallback) {
    const char* v = std::getenv(var);
    std::filesystem::path base = v && *v ? std::filesystem::path(v) : std::filesystem::path(home()) / fallback;
    return (base / "pwvault").string();
}

// "~/x" -> $HOME/x, relative -> base/x, absolute unchanged
std::string resolvePath(const std::string& p, const std::string& base) {
    if (p.empty()) return p;
    if (p == "~" || p.rfind("~/", 0) == 0) return home() + p.substr(1);
    std::filesystem::path path(p);
    return path.is_absolute() ? p : (std::filesystem::path(base) / path).string();
}
}  // namespace

std::string ConfigManager::configDir() {
    return xdgDir("XDG_CONFIG_HOME", ".config");
}

std::string ConfigManager::configFile() {
    return configDir() + "/config";
}

std::string ConfigManager::dataDir() {
    return xdgDir("XDG_DATA_HOME", ".local/share");
}

void ConfigManager::resolvePaths() {
    const std::string base = std::filesystem::path(configFile_).parent_path().string();
    config_.dataPath = config_.dataPath.empty() ? dataDir() : resolvePath(config_.dataPath, base);
    config_.espCert = resolvePath(config_.espCert, base);
    config_.espClientCert = resolvePath(config_.espClientCert, base);
    config_.espClientKey = resolvePath(config_.espClientKey, base);
}

bool ConfigManager::loadConfig(const std::string& configPath) {
    configFile_ = configPath;
    std::ifstream file(configPath);
    if (!file.is_open()) {
        std::error_code ec;
        if (std::filesystem::exists(configPath, ec)) {
            // Exists but unreadable: never overwrite it; almost always created by a `sudo` run
            std::cerr << "Cannot read " << configPath << ": permission denied.\n"
                      << "It is probably owned by root (created by running something with sudo). Fix it with:\n"
                      << "  sudo chown $USER " << configPath << "\n";
            resolvePaths();
            return false;
        }
        // First run: write the defaults so the user has a file to edit
        bool ok = saveConfig(configPath);
        resolvePaths();
        return ok;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Trim leading and trailing whitespace
        line.erase(0, line.find_first_not_of(" \t\n\r"));
        line.erase(line.find_last_not_of(" \t\n\r") + 1);
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Parse key=value pairs
        size_t equalPos = line.find('=');
        if (equalPos == std::string::npos) {
            continue;
        }

        std::string key = line.substr(0, equalPos);
        std::string value = line.substr(equalPos + 1);

        // Apply configuration values
        // "version" is ignored: it's a build fact, and a stale line from an older install would win.
        if (key == "dataPath") {
            config_.dataPath = value;
        } else if (key == "espHost") {
            config_.espHost = value;
        } else if (key == "localCopy") {
            config_.localCopy = !(value == "false" || value == "0");
        } else if (key == "espPort") {
            try {
                config_.espPort = std::stoi(value);
            } catch (const std::exception&) {  // empty or garbage: keep the default
            }
        } else if (key == "espClientCert") {
            config_.espClientCert = value;
        } else if (key == "espClientKey") {
            config_.espClientKey = value;
        } else if (key == "espCert") {
            config_.espCert = value;
        } else if (key == "maxLoginAttempts") {
            try {
                int attempts = std::stoi(value);
                if (attempts < 1) {
                    std::cerr << "Warning: Invalid max login attempts value in config: " << attempts << "\n";
                } else {
                    config_.maxLoginAttempts = attempts;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing maxLoginAttempts: " << e.what() << "\n";
            }
        } else if (key == "clipboardTimeoutSeconds") {
            try {
                int seconds = std::stoi(value);
                if (seconds < 0) {
                    std::cerr << "Warning: Invalid clipboard timeout value in config: " << seconds << "\n";
                } else {
                    config_.clipboardTimeoutSeconds = seconds;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing clipboardTimeoutSeconds: " << e.what() << "\n";
            }
        } else if (key == "autoClipboardClear") {
            config_.autoClipboardClear = (value == "true" || value == "1");
        } else if (key == "requirePasswordConfirmation") {
            config_.requirePasswordConfirmation = (value == "true" || value == "1");
        } else if (key == "minPasswordLength") {
            try {
                int length = std::stoi(value);
                if (length < 1) {
                    std::cerr << "Warning: Invalid min password length value in config: " << length << "\n";
                } else {
                    config_.minPasswordLength = length;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing minPasswordLength: " << e.what() << "\n";
            }
        } else if (key == "showEncryptionInCredentials") {
            config_.showEncryptionInCredentials = (value == "true" || value == "1");
        } else if (key == "theme") {
            config_.theme = value == "light" || value == "dark" ? value : "system";
        } else if (key == "defaultUIMode") {
            config_.defaultUIMode = value;
            // Normalize to lowercase for consistency
            std::transform(
                config_.defaultUIMode.begin(), config_.defaultUIMode.end(), config_.defaultUIMode.begin(), ::tolower);
        } else if (key == "githubOwner") {
            config_.githubOwner = value;
        } else if (key == "githubRepo") {
            config_.githubRepo = value;
        } else if (key == "autoCheckUpdates") {
            config_.autoCheckUpdates = (value == "true" || value == "1");
        } else if (key == "updateCheckIntervalDays") {
            try {
                int days = std::stoi(value);
                if (days > 0) {
                    config_.updateCheckIntervalDays = days;
                }
            } catch (const std::exception&) {
                // Keep default value if parsing fails
            }
        }
    }

    file.close();
    resolvePaths();
    return true;
}

bool ConfigManager::saveConfig(const std::string& configPath) {
    std::error_code dirErr;
    std::filesystem::create_directories(std::filesystem::path(configPath).parent_path(), dirErr);
    std::filesystem::permissions(std::filesystem::path(configPath).parent_path(), std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, dirErr);
    std::ofstream file(configPath);
    if (!file.is_open()) {
        std::cerr << "Failed to create config file: " << configPath << std::endl;
        return false;
    }

    // Write configuration file with comments
    file << "# Password Manager Configuration File\n";
    file << "# This file contains application settings and preferences\n\n";

    file << "# Core Settings\n";
    file << "dataPath=" << config_.dataPath << "\n";
    file << "maxLoginAttempts=" << config_.maxLoginAttempts << "\n\n";

    file << "# Clipboard Settings\n";
    file << "clipboardTimeoutSeconds=" << config_.clipboardTimeoutSeconds << "\n";
    file << "autoClipboardClear=" << (config_.autoClipboardClear ? "true" : "false") << "\n\n";

    file << "# Security Settings\n";
    file << "requirePasswordConfirmation=" << (config_.requirePasswordConfirmation ? "true" : "false") << "\n";
    file << "minPasswordLength=" << config_.minPasswordLength << "\n\n";

    file << "# UI Settings\n";
    file << "showEncryptionInCredentials=" << (config_.showEncryptionInCredentials ? "true" : "false") << "\n";
    file << "defaultUIMode=" << config_.defaultUIMode << "\n";
    file << "theme=" << config_.theme << "\n\n";

    file << "# ESP32 Vault (empty espHost = local only)\n";
    file << "espHost=" << config_.espHost << "\n";
    file << "# false = device-only: every read goes to the ESP32, nothing is stored on this machine\n";
    file << "localCopy=" << (config_.localCopy ? "true" : "false") << "\n";
    file << "espPort=" << config_.espPort << "\n";
    file << "espCert=" << config_.espCert << "\n";
    file << "espClientCert=" << config_.espClientCert << "\n";
    file << "espClientKey=" << config_.espClientKey << "\n\n";

    file << "# Update/Repository Settings\n";
    file << "githubOwner=" << config_.githubOwner << "\n";
    file << "githubRepo=" << config_.githubRepo << "\n";
    file << "autoCheckUpdates=" << (config_.autoCheckUpdates ? "true" : "false") << "\n";
    file << "updateCheckIntervalDays=" << config_.updateCheckIntervalDays << "\n";

    file.close();
    // Owner-only: it points at this device's private key for the ESP32
    std::error_code ec;
    std::filesystem::permissions(configPath, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    return true;
}

void ConfigManager::updateConfig(const AppConfig& newConfig) {
    config_ = newConfig;

    // Remove global variables for backward compatibility
}

void ConfigManager::setVersion(const std::string& version) {
    config_.version = version;
    saveConfig();
}
