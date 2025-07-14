#include "./cli_api.h"
#include "../core/api.h"
#include "../core/ui.h"
#include "../../GlobalConfig.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <string>

CliManager::CliManager(const std::string& dataPath) 
    : dataPath(dataPath), authenticated(false) {
}

void CliManager::printHelp() const {
    std::cout << "\n+-----------------------------------------------------------+\n";
    std::cout << "|                Password Manager CLI Help                 |\n";
    std::cout << "+-----------------------------------------------------------+\n";
    std::cout << "| Usage: password_manager [options]                        |\n";
    std::cout << "|                                                          |\n";
    std::cout << "| Options:                                                 |\n";
    std::cout << "|   -h, --help                Show this help message       |\n";
    std::cout << "|   --setup PASSWORD         First-time setup with password|\n";
    std::cout << "|   -a, --add PLATFORM USER PASS                           |\n";
    std::cout << "|                             Add new credentials          |\n";
    std::cout << "|   -s, --show                List all platforms           |\n";
    std::cout << "|   -g, --get PLATFORM        Show credentials for platform|\n";
    std::cout << "|   -d, --delete PLATFORM     Delete platform credentials  |\n";
    std::cout << "|   -p, --password NEW_PASS   Change master password       |\n";
    std::cout << "+-----------------------------------------------------------+\n";
}

bool CliManager::authenticate(const std::string& password) {
    CredentialsManager manager(dataPath);
    authenticated = manager.login(password);
    return authenticated;
}

bool CliManager::handleAddCredentials(const std::string& platform, const std::string& username, const std::string& password) {
    if (!authenticated) {
        std::cerr << "Error: Not authenticated. Please provide a valid password first." << std::endl;
        return false;
    }

    CredentialsManager manager(dataPath);
    bool success = manager.addCredentials(platform, username, password);
    
    if (success) {
        std::cout << "[SUCCESS] Credentials for '" << platform << "' added successfully." << std::endl;
    } else {
        std::cerr << "[ERROR] Failed to add credentials for '" << platform << "'." << std::endl;
    }
    
    return success;
}

bool CliManager::handleListPlatforms() {
    if (!authenticated) {
        std::cerr << "Error: Not authenticated. Please provide a valid password first." << std::endl;
        return false;
    }

    CredentialsManager manager(dataPath);
    std::vector<std::string> platforms = manager.getAllPlatforms();
    
    if (platforms.empty()) {
        std::cout << "No platforms found. Use --add to add new credentials." << std::endl;
        return true;
    }
    
    // Sort platforms alphabetically
    std::sort(platforms.begin(), platforms.end());
    
    // Display the platforms
    std::cout << "\n+-------------------------------------------+" << std::endl;
    std::cout << "|        Stored Platform Credentials       |" << std::endl;
    std::cout << "+-------------------------------------------+" << std::endl;
    
    for (size_t i = 0; i < platforms.size(); ++i) {
        std::cout << "| " << std::setw(3) << (i + 1) << ". " 
                  << std::left << std::setw(33) << platforms[i] << "|" << std::endl;
    }
    
    std::cout << "+-------------------------------------------+" << std::endl;
    return true;
}

bool CliManager::handleShowCredentials(const std::string& platform) {
    if (!authenticated) {
        std::cerr << "Error: Not authenticated. Please provide a valid password first." << std::endl;
        return false;
    }

    CredentialsManager manager(dataPath);
    std::vector<std::string> credentials = manager.getCredentials(platform);
    
    if (credentials.size() < 2) {
        std::cerr << "[ERROR] No credentials found for '" << platform << "'." << std::endl;
        return false;
    }
    
    // Display the credentials
    std::cout << "\n+---------------------------------------+" << std::endl;
    std::cout << "| Platform: " << std::left << std::setw(27) << platform << "|" << std::endl;
    std::cout << "+---------------------------------------+" << std::endl;
    std::cout << "| Username: " << std::left << std::setw(27) << credentials[0] << "|" << std::endl;
    std::cout << "| Password: " << std::left << std::setw(27) << credentials[1] << "|" << std::endl;
    std::cout << "+---------------------------------------+" << std::endl;
    
    return true;
}

bool CliManager::handleDeleteCredentials(const std::string& platform) {
    if (!authenticated) {
        std::cerr << "Error: Not authenticated. Please provide a valid password first." << std::endl;
        return false;
    }

    CredentialsManager manager(dataPath);
    bool success = manager.deleteCredentials(platform);
    
    if (success) {
        std::cout << "[SUCCESS] Credentials for '" << platform << "' deleted successfully." << std::endl;
    } else {
        std::cerr << "[ERROR] Failed to delete credentials for '" << platform << "'." << std::endl;
    }
    
    return success;
}

bool CliManager::handleChangePassword(const std::string& newPassword) {
    if (!authenticated) {
        std::cerr << "Error: Not authenticated. Please provide a valid password first." << std::endl;
        return false;
    }

    CredentialsManager manager(dataPath);
    bool success = manager.updatePassword(newPassword);
    
    if (success) {
        std::cout << "[SUCCESS] Master password updated successfully." << std::endl;
    } else {
        std::cerr << "[ERROR] Failed to update master password." << std::endl;
    }
    
    return success;
}

// First-time setup to create a master password without requiring authentication
bool CliManager::handleSetup(const std::string& newPassword) {
    CredentialsManager manager(dataPath);
    
    // Check if login file already exists
    std::filesystem::path loginPath = std::filesystem::path(dataPath) / "enter";
    if (std::filesystem::exists(loginPath)) {
        std::cerr << "Error: Password file already exists. Use the change password function instead." << std::endl;
        return false;
    }
    
    bool success = manager.updatePassword(newPassword);
    
    if (success) {
        std::cout << "[SUCCESS] Master password created successfully." << std::endl;
    } else {
        std::cerr << "[ERROR] Failed to create master password." << std::endl;
    }
    
    return success;
}

int CliManager::executeCommand(int argc, char* argv[]) {
    if (argc < 2) {
        printHelp();
        return 1;
    }

    std::string command = argv[1];
    
    // Check for help command first
    if (command == "-h" || command == "--help") {
        printHelp();
        return 0;
    }
    
    // Setup command doesn't need authentication
    if (command == "--setup") {
        if (argc < 3) {
            std::cerr << "Error: New password required. Use: " << argv[0] << " --setup <new_password>" << std::endl;
            return 1;
        }
        return handleSetup(argv[2]) ? 0 : 1;
    }
    
    // For all other commands, we need authentication
    if (argc < 3) {
        std::cerr << "Error: Password required. Use: " << argv[0] << " <command> <password> [options...]" << std::endl;
        return 1;
    }
    
    std::string password = argv[2];
    
    if (!authenticate(password)) {
        std::cerr << "Error: Invalid password." << std::endl;
        return 1;
    }
    
    // Process commands
    if (command == "-a" || command == "--add") {
        if (argc < 6) {
            std::cerr << "Error: Missing arguments for add command." << std::endl;
            std::cerr << "Usage: " << argv[0] << " -a <password> <platform> <username> <platform_password>" << std::endl;
            return 1;
        }
        return handleAddCredentials(argv[3], argv[4], argv[5]) ? 0 : 1;
    } 
    else if (command == "-s" || command == "--show") {
        return handleListPlatforms() ? 0 : 1;
    } 
    else if (command == "-g" || command == "--get") {
        if (argc < 4) {
            std::cerr << "Error: Missing platform name for get command." << std::endl;
            std::cerr << "Usage: " << argv[0] << " -g <password> <platform>" << std::endl;
            return 1;
        }
        return handleShowCredentials(argv[3]) ? 0 : 1;
    } 
    else if (command == "-d" || command == "--delete") {
        if (argc < 4) {
            std::cerr << "Error: Missing platform name for delete command." << std::endl;
            std::cerr << "Usage: " << argv[0] << " -d <password> <platform>" << std::endl;
            return 1;
        }
        return handleDeleteCredentials(argv[3]) ? 0 : 1;
    } 
    else if (command == "-p" || command == "--password") {
        if (argc < 4) {
            std::cerr << "Error: Missing new password for password change command." << std::endl;
            std::cerr << "Usage: " << argv[0] << " -p <old_password> <new_password>" << std::endl;
            return 1;
        }
        return handleChangePassword(argv[3]) ? 0 : 1;
    } 
    else {
        std::cerr << "Error: Unknown command '" << command << "'." << std::endl;
        printHelp();
        return 1;
    }
}

int cli_main(int argc, char **argv) {
    // Use the data path from GlobalConfig
    CliManager manager(data_path);
    return manager.executeCommand(argc, argv);
}