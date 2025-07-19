#include "GlobalConfig.h"
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

// Global variables (for backward compatibility)
std::string g_data_path = "./data";
std::vector<int> taps = {0, 2};
std::vector<int> init_state = {1, 0, 1};
EncryptionType g_encryption_type = EncryptionType::LFSR;

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
        // Remove whitespace and skip empty lines or comments
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
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
        if (key == "dataPath") {
            config_.dataPath = value;
        } else if (key == "defaultEncryption") {
            config_.defaultEncryption = parseEncryptionType(value);
        } else if (key == "maxLoginAttempts") {
            config_.maxLoginAttempts = std::stoi(value);
        } else if (key == "clipboardTimeoutSeconds") {
            config_.clipboardTimeoutSeconds = std::stoi(value);
        } else if (key == "autoClipboardClear") {
            config_.autoClipboardClear = (value == "true" || value == "1");
        } else if (key == "requirePasswordConfirmation") {
            config_.requirePasswordConfirmation = (value == "true" || value == "1");
        } else if (key == "minPasswordLength") {
            config_.minPasswordLength = std::stoi(value);
        } else if (key == "lfsrTaps") {
            config_.lfsrTaps = parseIntArray(value);
        } else if (key == "lfsrInitState") {
            config_.lfsrInitState = parseIntArray(value);
        } else if (key == "showEncryptionInCredentials") {
            config_.showEncryptionInCredentials = (value == "true" || value == "1");
        } else if (key == "defaultUIMode") {
            config_.defaultUIMode = value;
        }
    }
    
    // Update global variables for backward compatibility
    g_data_path = config_.dataPath;
    taps = config_.lfsrTaps;
    init_state = config_.lfsrInitState;
    g_encryption_type = config_.defaultEncryption;
    
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
    
    file << "# Core Settings\n";
    file << "dataPath=" << config_.dataPath << "\n";
    file << "defaultEncryption=" << encryptionTypeToString(config_.defaultEncryption) << "\n";
    file << "maxLoginAttempts=" << config_.maxLoginAttempts << "\n\n";
    
    file << "# Clipboard Settings\n";
    file << "clipboardTimeoutSeconds=" << config_.clipboardTimeoutSeconds << "\n";
    file << "autoClipboardClear=" << (config_.autoClipboardClear ? "true" : "false") << "\n\n";
    
    file << "# Security Settings\n";
    file << "requirePasswordConfirmation=" << (config_.requirePasswordConfirmation ? "true" : "false") << "\n";
    file << "minPasswordLength=" << config_.minPasswordLength << "\n\n";
    
    file << "# LFSR Algorithm Settings\n";
    file << "lfsrTaps=" << intArrayToString(config_.lfsrTaps) << "\n";
    file << "lfsrInitState=" << intArrayToString(config_.lfsrInitState) << "\n\n";
    
    file << "# UI Settings\n";
    file << "showEncryptionInCredentials=" << (config_.showEncryptionInCredentials ? "true" : "false") << "\n";
    file << "defaultUIMode=" << config_.defaultUIMode << "\n";
    
    file.close();
    return true;
}

void ConfigManager::updateConfig(const AppConfig& newConfig) {
    config_ = newConfig;
    
    // Update global variables for backward compatibility
    g_data_path = config_.dataPath;
    taps = config_.lfsrTaps;
    init_state = config_.lfsrInitState;
    g_encryption_type = config_.defaultEncryption;
}

void ConfigManager::setDataPath(const std::string& path) {
    config_.dataPath = path;
    g_data_path = path;
}

void ConfigManager::setDefaultEncryption(EncryptionType type) {
    config_.defaultEncryption = type;
    g_encryption_type = type;
}

void ConfigManager::setClipboardTimeout(int seconds) {
    config_.clipboardTimeoutSeconds = seconds;
}

EncryptionType ConfigManager::parseEncryptionType(const std::string& value) const {
    if (value == "LFSR" || value == "0") {
        return EncryptionType::LFSR;
    } else if (value == "AES" || value == "1") {
        return EncryptionType::AES;
    } else if (value == "AES_LFSR" || value == "2") {
        return EncryptionType::AES_LFSR;
    }
    return EncryptionType::AES_LFSR; // Default fallback
}

std::string ConfigManager::encryptionTypeToString(EncryptionType type) const {
    switch (type) {
        case EncryptionType::LFSR:
            return "LFSR";
        case EncryptionType::AES:
            return "AES";
        case EncryptionType::AES_LFSR:
            return "AES_LFSR";
        default:
            return "AES_LFSR";
    }
}

std::vector<int> ConfigManager::parseIntArray(const std::string& value) const {
    std::vector<int> result;
    std::stringstream ss(value);
    std::string item;
    
    while (std::getline(ss, item, ',')) {
        try {
            result.push_back(std::stoi(item));
        } catch (const std::exception&) {
            // Skip invalid values
        }
    }
    
    return result;
}

std::string ConfigManager::intArrayToString(const std::vector<int>& array) const {
    std::stringstream ss;
    for (size_t i = 0; i < array.size(); ++i) {
        if (i > 0) ss << ",";
        ss << array[i];
    }
    return ss.str();
}

// Implementation of EncryptionUtils helper functions
namespace EncryptionUtils {
    
    const char* getDisplayName(EncryptionType type) {
        switch (type) {
            case EncryptionType::LFSR:
                return "LFSR (Basic)";
            case EncryptionType::AES:
                return "AES-256 (Strong)";
            case EncryptionType::AES_LFSR:
                return "AES-256 with LFSR (Strongest)";
            default:
                return "Unknown";
        }
    }
    
    std::vector<EncryptionType> getAllTypes() {
        std::vector<EncryptionType> types;
        for (int i = 0; i < static_cast<int>(EncryptionType::COUNT); ++i) {
            types.push_back(static_cast<EncryptionType>(i));
        }
        return types;
    }
    
    EncryptionType fromDropdownIndex(int index) {
        if (index >= 0 && index < static_cast<int>(EncryptionType::COUNT)) {
            return static_cast<EncryptionType>(index);
        }
        return getDefault(); // Fallback to default if invalid index
    }
    
    int toDropdownIndex(EncryptionType type) {
        return static_cast<int>(type);
    }
    
    EncryptionType getDefault() {
        return EncryptionType::AES_LFSR; // Default to strongest encryption for new users
    }
    
    const std::map<int, EncryptionType>& getChoiceMapping() {
        static std::map<int, EncryptionType> choiceMap;
        
        // Build the map dynamically if it's empty
        if (choiceMap.empty()) {
            int choice = 1; // Start menu choices from 1
            for (int i = 0; i < static_cast<int>(EncryptionType::COUNT); ++i) {
                choiceMap[choice++] = static_cast<EncryptionType>(i);
            }
        }
        
        return choiceMap;
    }
}