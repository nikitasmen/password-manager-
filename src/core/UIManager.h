#ifndef UI_MANAGER_H
#define UI_MANAGER_H

#include <string>
#include <vector>
#include <memory>
#include "api.h" // Include complete CredentialsManager definition
#include "../config/GlobalConfig.h"

/**
 * @class UIManager
 * @brief Abstract base class for UI implementations
 * 
 * This class defines the interface that all UI implementations 
 * (terminal-based, graphical, etc.) must implement to provide
 * a consistent way to interact with the password manager.
 */
class UIManager {
protected:
    // Common data shared by all UI implementations
    std::unique_ptr<CredentialsManager> credManager;
    bool isLoggedIn;
    std::string masterPassword;
    std::string dataPath;

    bool safeAddCredential(const std::string& platform, const std::string& username, const std::string& password, std::optional<EncryptionType> encryptionType);
    std::optional<DecryptedCredential> safeGetCredentials(const std::string& platform);
    bool safeDeleteCredential(const std::string& platform);

public:
    /**
     * @brief Constructor
     * @param dataPath Path to the data storage directory
     */
    UIManager(const std::string& dataPath);
    
    /**
     * @brief Virtual destructor
     */
    virtual ~UIManager() = default;
    
    /**
     * @brief Initialize the UI
     */
    virtual void initialize() = 0;
    
    /**
     * @brief Show the UI and start the event loop
     * @return Exit code
     */
    virtual int show() = 0;
    
    /**
     * @brief Handle user login
     * @param password User's master password
     * @return True if login was successful
     */
    virtual bool login(const std::string& password) = 0;
    
    /**
     * @brief Set up a new master password
     * @param newPassword New master password
     * @param confirmPassword Password confirmation
     * @param encryptionType The encryption algorithm to use
     * @return True if password setup was successful
     */
    virtual bool setupPassword(const std::string& newPassword, 
                              const std::string& confirmPassword,
                              EncryptionType encryptionType) = 0;
    
    /**
     * @brief Add a new credential
     * @param platform Platform name
     * @param username Username
     * @param password Password
     * @param encryptionType The encryption algorithm to use (default: user selection)
     * @return True if credential was added successfully
     */
    virtual bool addCredential(const std::string& platform, 
                              const std::string& username, 
                              const std::string& password,
                              std::optional<EncryptionType> encryptionType = std::nullopt) = 0;
    
    /**
     * @brief View credentials for a platform
     * @param platform Platform name
     */
    virtual void viewCredential(const std::string& platform) = 0;
    
    /**
     * @brief Delete credentials for a platform
     * @param platform Platform name
     * @return True if credentials were deleted successfully
     */
    virtual bool deleteCredential(const std::string& platform) = 0;
    
    /**
     * @brief Update existing credentials for a platform
     * @param platform Platform name
     * @param username Username (unchanged)
     * @param password New password
     * @return True if credentials were updated successfully
     */
    virtual bool updateCredential(const std::string& platform, 
                                 const std::string& username, 
                                 const std::string& password) = 0;
    
    /**
     * @brief Display a message to the user
     * @param title Message title
     * @param message Message content
     * @param isError Whether this is an error message
     */
    virtual void showMessage(const std::string& title, const std::string& message, bool isError = false) = 0;
    
    /**
     * @brief Get a fresh credentials manager instance
     * @return New credentials manager with current login state
     */
    std::unique_ptr<CredentialsManager> getFreshCredManager();
};

#endif // UI_MANAGER_H
