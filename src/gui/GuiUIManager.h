#ifndef GUI_UI_MANAGER_H
#define GUI_UI_MANAGER_H

#include <FL/Fl_Double_Window.H>

#include <chrono>
#include <functional>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "../core/UIManager.h"

class Fl_Box;
class Fl_Button;
class Fl_Input;
class Fl_Secret_Input;
class OledPanel;
class EntryList;
class UpdateDialog;

/**
 * FLTK front end. Two windows: unlock/create, and the vault (entry list + detail pane, with the ESP32's
 * screen as a status strip). Add/edit and settings are modal dialogs. All vault access goes through UIManager.
 */
class GuiUIManager : public UIManager {
   public:
    explicit GuiUIManager(const std::string& dataPath);
    ~GuiUIManager() override;

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
    void viewCredential(const std::string& platform) override;  // selects it in the list
    bool deleteCredential(const std::string& platform) override;
    bool updateCredential(const std::string& platform,
                          const std::string& username,
                          const std::string& password,
                          std::optional<CipherAlg> encryptionType = std::nullopt) override;
    void showMessage(const std::string& title, const std::string& message, bool isError = false) override;

   private:
    void buildUnlockWindow(bool create);
    void buildVaultWindow();
    void refreshList(const std::string& select = "");
    void showDetail(std::optional<Credential> cred);
    void editEntry(const std::optional<Credential>& existing);  // modal add/edit dialog
    void openSettings();                                         // modal settings dialog
    void openDevices();                                          // modal: hosts, and the devices paired with each
    std::string addHostDialog(const std::string& at = "");       // modal: pair with a host; its id, "" if not
    void showPairingCode(const EspStore::PairInvite& invite);    // modal: the QR a phone scans to pair
    void changeMasterPassword();                                 // modal: current + new + repeat
    void setPinDialog();                                         // modal: master password + PIN + repeat
    bool loginWithPin(const std::string& pin);
    bool usePassword_ = false;  // unlock with the master password even though a PIN is set
    void runConnector();  // on start: pair with / reach the ESP32, unless it's already connected
    void lockVault();
    void copy(const std::string& text, const std::string& what);
    void flash(const std::string& event);  // a transient line on the OLED strip, like the board's events
    void drawStrip();
    void drawUnlockOled();
    static void tick(void* self);  // 1 s clock for both OLEDs

    // FLTK callbacks are C function pointers; this keeps lambdas alive for the window that uses them
    std::list<std::function<void()>> callbacks_;
    void on(Fl_Widget* w, std::function<void()> f);

    std::unique_ptr<Fl_Double_Window> unlockWin_, vaultWin_;
    std::unique_ptr<UpdateDialog> updateDialog_;

    // unlock window
    OledPanel* unlockOled_ = nullptr;
    Fl_Secret_Input* pass1_ = nullptr;
    Fl_Secret_Input* pass2_ = nullptr;  // confirm, create mode only
    Fl_Box* unlockError_ = nullptr;

    // vault window
    OledPanel* strip_ = nullptr;
    Fl_Input* search_ = nullptr;
    EntryList* list_ = nullptr;
    Fl_Box* title_ = nullptr;
    Fl_Box* hint_ = nullptr;
    Fl_Box* userLabel_ = nullptr;
    Fl_Box* userValue_ = nullptr;
    Fl_Box* passLabel_ = nullptr;
    Fl_Box* passValue_ = nullptr;
    Fl_Box* passShown_ = nullptr;  // the revealed password, on its own full-width line
    Fl_Box* algLabel_ = nullptr;
    Fl_Box* algValue_ = nullptr;
    Fl_Button* copyUser_ = nullptr;
    Fl_Button* copyPass_ = nullptr;
    Fl_Button* reveal_ = nullptr;
    Fl_Button* edit_ = nullptr;
    Fl_Button* delete_ = nullptr;

    std::vector<std::string> platforms_;  // cached for filtering; refreshed after writes
    std::optional<Credential> current_;
    std::string selected_;  // survives a search that hides it, so clearing the search brings it back
    bool revealed_ = false;
    std::string event_;
    std::chrono::steady_clock::time_point eventUntil_{};
};

#endif  // GUI_UI_MANAGER_H
