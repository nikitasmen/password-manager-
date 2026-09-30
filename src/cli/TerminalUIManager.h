#ifndef TERMINAL_UI_MANAGER_H
#define TERMINAL_UI_MANAGER_H

#include <string>
#include <vector>

#include "../core/UIManager.h"

/**
 * Terminal front end. Home is the entry list (type a number or a name to open one); a one-line key legend
 * sits at the bottom of every screen, and the board's OLED sits at the top.
 */
class TerminalUIManager : public UIManager {
   public:
    explicit TerminalUIManager(const std::string& dataPath);

    void initialize() override;
    int show() override;
    bool login(const std::string& password) override;
    bool setupPassword(const std::string& newPassword,
                       const std::string& confirmPassword,
                       CipherAlg encryptionType) override;
    bool addCredential(const std::string& platform,
                       const std::string& username,
                       const std::string& password,
                       std::optional<CipherAlg> encryptionType = std::nullopt) override;
    void viewCredential(const std::string& platform) override;
    bool deleteCredential(const std::string& platform) override;
    bool updateCredential(const std::string& platform,
                          const std::string& username,
                          const std::string& password,
                          std::optional<CipherAlg> encryptionType = std::nullopt) override;
    void showMessage(const std::string& title, const std::string& message, bool isError = false) override;

   private:
    bool unlockScreen();  // false = give up (too many attempts)
    void home();          // the entry list; returns on lock or quit
    void header(const std::string& state);
    void newEntry();
    void editEntry(const Credential& c);
    void changeMasterPassword();
    void devicesScreen();  // devices paired with the ESP32

    std::string message_;  // shown once, at the top of the next screen
    bool quit_ = false;
    bool create_ = false;  // no vault yet
};

#endif  // TERMINAL_UI_MANAGER_H
