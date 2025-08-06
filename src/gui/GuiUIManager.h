#ifndef GUI_UI_MANAGER_H
#define GUI_UI_MANAGER_H

#include "../core/UIManager.h"
// Forward declare component classes to avoid circular dependencies
class ContainerComponent;
class LoginFormComponent;
class PasswordSetupComponent;
class PlatformsDisplayComponent;
class CredentialInputsComponent;
class SettingsDialogComponent;
class ClickablePlatformsDisplay;
class UpdateDialog;
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/fl_message.H>
#include <vector>
#include <memory>
#include <string>
#include <functional>
#include "../core/credential_data.h"

/**
 * @class GuiUIManager
 * @brief Graphical UI implementation of UIManager
 * 
 * This class implements the UIManager interface to provide
 * a graphical user interface for the password manager.
 */
class GuiUIManager : public UIManager {
private:
    // Main window
    std::unique_ptr<Fl_Window> mainWindow;
    
    // Root component
    std::unique_ptr<ContainerComponent> rootComponent;
    
    // Dialog windows and their root components
    std::unique_ptr<Fl_Window> addCredentialWindow;
    std::unique_ptr<ContainerComponent> addCredentialRoot;
    std::unique_ptr<Fl_Window> viewCredentialWindow;
    std::unique_ptr<ContainerComponent> viewCredentialRoot;
    std::unique_ptr<Fl_Window> updatePasswordWindow;  // Added for update password dialog
    std::unique_ptr<Fl_Window> settingsWindow;
    std::unique_ptr<ContainerComponent> settingsRoot;
    
    // Update dialog
    std::unique_ptr<UpdateDialog> updateDialog;
    
    // Component references
    LoginFormComponent* loginForm;
    PasswordSetupComponent* passwordSetup;
    PlatformsDisplayComponent* platformsDisplay; // Kept for backward compatibility
    ClickablePlatformsDisplay* clickablePlatformsDisplay;
    CredentialInputsComponent* credentialInputs;
    
    // Current credential being updated
    std::string currentPlatform;
    DecryptedCredential currentCredential;

    // Private helper methods
    void createLoginScreen();
    void createSetupScreen();
    void createMainScreen();
    void createAddCredentialDialog();
    void createViewCredentialDialog(const std::string& platform, const std::optional<DecryptedCredential>& credentials);
    void createUpdatePasswordDialog();  // Added for update password dialog
    void createSettingsDialog();
    
    /**
     * @brief Clean up the add credential dialog (uses generic helper)
     */
    void cleanupAddCredentialDialog();
    /**
     * @brief Clean up the view credential dialog (uses generic helper)
     */
    void cleanupViewCredentialDialog();
    /**
     * @brief Clean up the update password dialog
     */
    void cleanupUpdatePasswordDialog();  // Added for update password dialog
    /**
     * @brief Clean up the settings dialog (uses generic helper)
     */
    void cleanupSettingsDialog();
    void cleanupMainWindow();
    void refreshPlatformsList();
    void setWindowCloseHandler(Fl_Window* window, bool exitOnClose = false);

    // Helper to reduce boilerplate in screen creation
    void createScreen(const std::string& title, int w, int h, std::function<void()> populateScreen);

public:
    /**
     * @brief Constructor
     * @param dataPath Path to the data storage directory
     */
    GuiUIManager(const std::string& dataPath);
    
    /**
     * @brief Destructor
     */
    ~GuiUIManager() override;
    
    /**
     * @brief Initialize the GUI
     */
    void initialize() override;
    
    /**
     * @brief Show the GUI and start the event loop
     * @return Exit code
     */
    int show() override;
    
    /**
     * @brief Handle user login in GUI
     * @param password User's master password
     * @return True if login was successful
     */
    bool login(const std::string& password) override;
    
    /**
     * @brief Set up a new master password through GUI
     * @param newPassword New master password
     * @param confirmPassword Password confirmation
     * @param encryptionType The encryption algorithm to use
     * @return True if password setup was successful
     */
bool setupPassword(const std::string& newPassword, 
                  const std::string& confirmPassword,
                  EncryptionType encryptionType) override;
    
    /**
     * @brief Add a new credential through GUI
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
     * @brief View credentials for a platform in GUI
     * @param platform Platform name
     */
    void viewCredential(const std::string& platform) override;
    
    /**
     * @brief Delete credentials for a platform through GUI
     * @param platform Platform name
     * @return True if credentials were deleted successfully
     */
    bool deleteCredential(const std::string& platform) override;

    /**
     * @brief Update existing credentials for a platform
     * @param platform Platform name
     * @param username Username (unchanged)
     * @param password New password
     * @param encryptionType Optional new encryption type (if not specified, preserves existing type)
     * @return True if credentials were updated successfully
     */
    bool updateCredential(const std::string& platform, 
                         const std::string& username,
                         const std::string& password,
                         std::optional<EncryptionType> encryptionType = std::nullopt) override;

    /**
     * @brief Display a message in GUI
     * @param title Message title
     * @param message Message content
     * @param isError Whether this is an error message
     */
    void showMessage(const std::string& title, const std::string& message, bool isError = false) override;
    
    /**
     * @brief Open the settings dialog
     */
    void openSettingsDialog();
    
    /**
     * @brief Open the update dialog
     */
    void openUpdateDialog();
};

#endif // GUI_UI_MANAGER_H
