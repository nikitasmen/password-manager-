#ifndef CLI_API_H
#define CLI_API_H

#include <string>
#include <vector>

/**
 * @class CliManager
 * @brief Command-line interface manager for password operations
 * 
 * Provides a CLI interface to the password manager functionality
 * with command parsing and execution capabilities
 */
class CliManager {
private:
    std::string dataPath;
    bool authenticated;
    
    /**
     * @brief Print usage instructions
     */
    void printHelp() const;
    
    /**
     * @brief Authenticate user with password
     * 
     * @param password User's master password
     * @return bool True if authentication successful
     */
    bool authenticate(const std::string& password);
    
    /**
     * @brief Handle adding new credentials
     * 
     * @param platform Platform name
     * @param username Username for the platform
     * @param password Password for the platform
     * @return bool True if operation successful
     */
    bool handleAddCredentials(const std::string& platform, 
                             const std::string& username, 
                             const std::string& password);
    
    /**
     * @brief List all stored platforms
     * 
     * @return bool True if operation successful
     */
    bool handleListPlatforms();
    
    /**
     * @brief Show credentials for a platform
     * 
     * @param platform Platform name to show
     * @return bool True if operation successful
     */
    bool handleShowCredentials(const std::string& platform);
    
    /**
     * @brief Delete credentials for a platform
     * 
     * @param platform Platform name to delete
     * @return bool True if operation successful
     */
    bool handleDeleteCredentials(const std::string& platform);
    
    /**
     * @brief Change the master password
     * 
     * @param newPassword New password to set
     * @return bool True if operation successful
     */
    bool handleChangePassword(const std::string& newPassword);
    
    /**
     * @brief First-time setup to create a master password
     * 
     * @param newPassword The password to set initially
     * @return bool True if setup was successful
     */
    bool handleSetup(const std::string& newPassword);

public:
    /**
     * @brief Construct a new Cli Manager object
     * 
     * @param dataPath Path for data storage
     */
    explicit CliManager(const std::string& dataPath = ".");
    
    /**
     * @brief Parse and execute command-line arguments
     * 
     * @param argc Argument count
     * @param argv Argument vector
     * @return int Exit code (0 for success)
     */
    int executeCommand(int argc, char* argv[]);
};

// Main function for CLI API
int cli_main(int argc, char** argv);

#endif // CLI_API_H