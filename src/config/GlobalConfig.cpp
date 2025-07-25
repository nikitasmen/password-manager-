#include "GlobalConfig.h"
#include "MigrationHelper.h"
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

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
    
    // Remove global variables for backward compatibility
    // g_data_path = config_.dataPath;
    // taps = config_.lfsrTaps;
    // init_state = config_.lfsrInitState;
    // g_encryption_type = config_.defaultEncryption;
    
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
    
    // Remove global variables for backward compatibility
    // g_data_path = config_.dataPath;
    // taps = config_.lfsrTaps;
    // init_state = config_.lfsrInitState;
    // g_encryption_type = config_.defaultEncryption;
}

void ConfigManager::setDataPath(const std::string& path) {
    config_.dataPath = path;
    // g_data_path = path; // Removed global update
}

void ConfigManager::setDefaultEncryption(EncryptionType type, const std::string& masterPassword) {
    // Only migrate if encryption type is changing and master password is provided
    if (type != config_.defaultEncryption && !masterPassword.empty()) {
        MigrationHelper& migrationHelper = MigrationHelper::getInstance();
        bool migrated = migrationHelper.migrateMasterPasswordForEncryptionChange(
            config_.defaultEncryption, type,
            config_.lfsrTaps, config_.lfsrInitState,
            config_.lfsrTaps, config_.lfsrInitState,
            masterPassword, config_.dataPath);
        if (!migrated) {
            std::cerr << "Warning: Master password migration failed during encryption type change." << std::endl;
        }
    }
    config_.defaultEncryption = type;
    // g_encryption_type = type; // Removed global update
}

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
    config_.defaultUIMode = mode;
}

void ConfigManager::setLfsrTaps(const std::vector<int>& newTaps) {
    // Validate that taps array is not empty
    if (newTaps.empty()) {
        std::cerr << "Warning: Empty LFSR taps provided, using default {0, 2}\n";
        config_.lfsrTaps = {0, 2};
        // taps = {0, 2}; // Removed global update
        return;
    }
    
    config_.lfsrTaps = newTaps;
    // taps = newTaps; // Removed global update
}

void ConfigManager::setLfsrInitState(const std::vector<int>& newInitState) {
    // Validate that init state is not empty
    if (newInitState.empty()) {
        std::cerr << "Warning: Empty LFSR initial state provided, using default {1, 0, 1}\n";
        config_.lfsrInitState = {1, 0, 1};
        // init_state = {1, 0, 1}; // Removed global update
        return;
    }
    
    // Validate that init state only contains 0s and 1s
    bool validInitState = true;
    for (int val : newInitState) {
        if (val != 0 && val != 1) {
            validInitState = false;
            break;
        }
    }
    
    if (!validInitState) {
        std::cerr << "Warning: LFSR initial state must contain only 0s and 1s, using default {1, 0, 1}\n";
        config_.lfsrInitState = {1, 0, 1};
        // init_state = {1, 0, 1}; // Removed global update
        return;
    }
    
    config_.lfsrInitState = newInitState;
    // init_state = newInitState; // Removed global update
}

bool ConfigManager::updateLfsrSettings(const std::vector<int>& newTaps, const std::vector<int>& newInitState, const std::string& masterPassword) {
    // Validate inputs
    if (newTaps.empty()) {
        std::cerr << "Error: LFSR taps cannot be empty\n";
        return false;
    }
    
    if (newInitState.empty()) {
        std::cerr << "Error: LFSR initial state cannot be empty\n";
        return false;
    }
    
    if (masterPassword.empty()) {
        std::cerr << "Error: Master password is required for LFSR settings update\n";
        return false;
    }
    
    // Store old settings in case of failure
    auto oldTaps = config_.lfsrTaps;
    auto oldInitState = config_.lfsrInitState;
    
    try {
        // Migrate existing credentials with the new LFSR settings
        std::cout << "Updating LFSR settings and migrating existing data..." << std::endl;
        
        MigrationHelper& migrationHelper = MigrationHelper::getInstance();
        bool migrationSuccess = migrationHelper.migrateCredentialsForLfsrChange(
            oldTaps, oldInitState, newTaps, newInitState, masterPassword, config_.dataPath);
        
        if (!migrationSuccess) {
            std::cerr << "Migration failed - reverting LFSR settings" << std::endl;
            // Restore old settings
            config_.lfsrTaps = oldTaps;
            config_.lfsrInitState = oldInitState;
            // taps = oldTaps; // Removed global update
            // init_state = oldInitState; // Removed global update
            return false;
        }
        
        // Update settings after successful migration
        config_.lfsrTaps = newTaps;
        config_.lfsrInitState = newInitState;
        // taps = newTaps; // Removed global update
        // init_state = newInitState; // Removed global update
        
        std::cout << "LFSR settings updated and data migration completed successfully" << std::endl;
        return true;
    } catch (const std::exception& e) {
        // Restore old settings if anything fails
        std::cerr << "Error updating LFSR settings: " << e.what() << "\n";
        config_.lfsrTaps = oldTaps;
        config_.lfsrInitState = oldInitState;
        // taps = oldTaps; // Removed global update
        // init_state = oldInitState; // Removed global update
        return false;
    }
}

// Implementation of EncryptionUtils helper functions

EncryptionType ConfigManager::parseEncryptionType(const std::string& value) const {
    if (value == "LFSR" || value == "0") {
        return EncryptionType::LFSR;
    } else if (value == "AES" || value == "1") {
        return EncryptionType::AES;
    }
    return EncryptionType::AES; // Default fallback
}

std::string ConfigManager::encryptionTypeToString(EncryptionType type) const {
    switch (type) {
        case EncryptionType::LFSR:
            return "LFSR";
        case EncryptionType::AES:
            return "AES";
        default:
            return "Unknown";
    }
}

std::vector<int> ConfigManager::parseIntArray(const std::string& value) const {
    std::vector<int> result;
    std::stringstream ss(value);
    std::string item;
    
    while (std::getline(ss, item, ',')) {
        try {
            // Validate that the string contains only digits
            if (item.empty() || !std::all_of(item.begin(), item.end(), [](char c) { 
                return std::isdigit(c) || c == '-'; // Allow negative numbers
            })) {
                std::cerr << "Warning: Invalid integer value '" << item << "' skipped\n";
                continue;
            }
            result.push_back(std::stoi(item));
        } catch (const std::exception& e) {
            std::cerr << "Warning: Failed to parse integer '" << item << "': " << e.what() << "\n";
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
        return EncryptionType::AES; // Default to strongest encryption for new users
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