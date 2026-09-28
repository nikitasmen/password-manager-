#include "GlobalConfig.h"

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

bool ConfigManager::loadConfig(const std::string& configPath) {
    std::ifstream file(configPath);
    if (!file.is_open()) {
        // Create default config file if it doesn't exist
        return saveConfig(configPath);
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
        if (key == "version") {
            config_.version = value;
        } else if (key == "dataPath") {
            config_.dataPath = value;
        } else if (key == "defaultCipher") {
            if (auto alg = cipherFromName(value)) config_.defaultCipher = *alg;
        } else if (key == "espHost") {
            config_.espHost = value;
        } else if (key == "espPort") {
            config_.espPort = std::stoi(value);
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

    // Remove global variables for backward compatibility

    file.close();
    return true;
}

bool ConfigManager::saveConfig(const std::string& configPath) {
    std::ofstream file(configPath);
    if (!file.is_open()) {
        std::cerr << "Failed to create config file: " << configPath << std::endl;
        return false;
    }

    // Write configuration file with comments
    file << "# Password Manager Configuration File\n";
    file << "# This file contains application settings and preferences\n\n";

    file << "# Application Version\n";
    file << "version=" << config_.version << "\n\n";

    file << "# Core Settings\n";
    file << "dataPath=" << config_.dataPath << "\n";
    file << "defaultCipher=" << cipherName(config_.defaultCipher) << "\n";
    file << "maxLoginAttempts=" << config_.maxLoginAttempts << "\n\n";

    file << "# Clipboard Settings\n";
    file << "clipboardTimeoutSeconds=" << config_.clipboardTimeoutSeconds << "\n";
    file << "autoClipboardClear=" << (config_.autoClipboardClear ? "true" : "false") << "\n\n";

    file << "# Security Settings\n";
    file << "requirePasswordConfirmation=" << (config_.requirePasswordConfirmation ? "true" : "false") << "\n";
    file << "minPasswordLength=" << config_.minPasswordLength << "\n\n";

    file << "# UI Settings\n";
    file << "showEncryptionInCredentials=" << (config_.showEncryptionInCredentials ? "true" : "false") << "\n";
    file << "defaultUIMode=" << config_.defaultUIMode << "\n\n";

    file << "# ESP32 Vault (empty espHost = local only)\n";
    file << "espHost=" << config_.espHost << "\n";
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

void ConfigManager::setDataPath(const std::string& path) {
    config_.dataPath = path;
}

// Deprecated: Use the new method that accepts LFSR settings
void ConfigManager::setMaxLoginAttempts(int attempts) {
    // Validate input range
    if (attempts < 1) {
        std::cerr << "Warning: Invalid max login attempts value " << attempts
                  << " (must be at least 1), setting to default (3)\n";
        attempts = 3;
    }
    config_.maxLoginAttempts = attempts;
}

void ConfigManager::setClipboardTimeoutSeconds(int seconds) {
    // Validate input range
    if (seconds < 0) {
        std::cerr << "Warning: Invalid clipboard timeout value " << seconds
                  << " (must be non-negative), setting to default (30)\n";
        seconds = 30;
    }
    config_.clipboardTimeoutSeconds = seconds;
}

void ConfigManager::setAutoClipboardClear(bool enabled) {
    config_.autoClipboardClear = enabled;
}

void ConfigManager::setRequirePasswordConfirmation(bool required) {
    config_.requirePasswordConfirmation = required;
}

void ConfigManager::setMinPasswordLength(int length) {
    // Validate input range
    if (length < 1) {
        std::cerr << "Warning: Invalid minimum password length " << length
                  << " (must be at least 1), setting to default (8)\n";
        length = 8;
    }
    config_.minPasswordLength = length;
}

void ConfigManager::setShowEncryptionInCredentials(bool show) {
    config_.showEncryptionInCredentials = show;
}

void ConfigManager::setDefaultUIMode(const std::string& mode) {
    // Convert to lowercase and store
    config_.defaultUIMode = mode;
    std::transform(
        config_.defaultUIMode.begin(), config_.defaultUIMode.end(), config_.defaultUIMode.begin(), ::tolower);
}

void ConfigManager::setGithubOwner(const std::string& owner) {
    config_.githubOwner = owner;
}

void ConfigManager::setGithubRepo(const std::string& repo) {
    config_.githubRepo = repo;
}

void ConfigManager::setAutoCheckUpdates(bool enabled) {
    config_.autoCheckUpdates = enabled;
}

void ConfigManager::setUpdateCheckIntervalDays(int days) {
    if (days > 0) {
        config_.updateCheckIntervalDays = days;
    } else {
        std::cerr << "Warning: Invalid update check interval " << days
                  << " (must be positive), keeping current value\n";
    }
}

// Implementation of EncryptionUtils helper functions

