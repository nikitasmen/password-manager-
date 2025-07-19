#ifndef TERMINAL_UI_MANAGER_H
#define TERMINAL_UI_MANAGER_H

#include "../core/UIManager.h"
#include "../core/terminal_ui.h"
#include <vector>

/**
 * @class TerminalUIManager
 * @brief Terminal-based implementation of UIManager
 * 
 * This class implements the UIManager interface to provide
 * a terminal-based user interface for the password manager.
 */
class TerminalUIManager : public UIManager {
private:
    // Terminal UI specific properties and methods

public:
    /**
     * @brief Constructor
     * @param dataPath Path to the data storage directory
     */
    TerminalUIManager(const std::string& dataPath);
    
    /**
     * @brief Initialize the terminal UI
     */
    void initialize() override;
    
    /**
     * @brief Show the terminal UI and start the command loop
     * @return Exit code
     */
    int show() override;
    
    /**
     * @brief Handle user login in terminal
     * @param password User's master password
     * @return True if login was successful
     */
    bool login(const std::string& password) override;
    
    /**
     * @brief Set up a new master password through terminal
     * @param newPassword New master password
     * @param confirmPassword Password confirmation
     * @param encryptionType The encryption algorithm to use
     * @return True if password setup was successful
     */
    bool setupPassword(const std::string& newPassword, 
                      const std::string& confirmPassword,
                      EncryptionType encryptionType = EncryptionType::AES_LFSR) override;
    
    /**
     * @brief Add a new credential through terminal
     * @param platform Platform name
     * @param username Username
     * @param password Password
     * @param encryptionType The encryption algorithm to use (optional)
     * @return True if credential was added successfully
     */
    bool addCredential(const std::string& platform, 
                      const std::string& username, 
                      const std::string& password,
                      std::optional<EncryptionType> encryptionType = std::nullopt) override;
    
    /**
     * @brief View credentials for a platform in terminal
     * @param platform Platform name
     */
    void viewCredential(const std::string& platform) override;
    
    /**
     * @brief Delete credentials for a platform through terminal
     * @param platform Platform name
     * @return True if credentials were deleted successfully
     */
    bool deleteCredential(const std::string& platform) override;
    
    /**
     * @brief Display a message in terminal
     * @param title Message title
     * @param message Message content
     * @param isError Whether this is an error message
     */
    void showMessage(const std::string& title, const std::string& message, bool isError = false) override;
    
    /**
     * @brief Run the main terminal menu loop
     * @return Exit code
     */
    int runMenuLoop();
};

#endif // TERMINAL_UI_MANAGER_H
