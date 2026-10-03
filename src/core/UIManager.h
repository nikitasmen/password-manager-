#ifndef UI_MANAGER_H
#define UI_MANAGER_H

#include <memory>
#include <string>
#include <vector>

#include "../config/GlobalConfig.h"
#include "../vault/EspStore.h"
#include "../vault/Pairing.h"
#include "../vault/PinUnlock.h"
#include "../vault/VaultService.h"

// A host this device is paired with (PROTOCOL.md §6). The config's esp* keys hold the first one (the connector's
// board); hosts added later live in hostsDir()/<id prefix>/.
struct PairedHost {
    std::string id;       // hex SHA-256 of its server cert; "" before pairing
    std::string address;  // as the user gave it: IP or name, with ":port" when it isn't 443
    HostRole role = HostRole::Dedicated;
    std::string dir;  // its folder; "" = the config's esp* host
    EspStore* store = nullptr;
};
std::string hostsDir();  // configDir()/hosts
// The paired hosts on disk, with what it takes to reach each (store unset); the config's host first.
// withHostsDir false: only the config's host (device-only mode). Also used by --serve, to sync as a client.
std::vector<std::pair<PairedHost, EspConfig>> loadPairedHosts(bool withHostsDir = true);

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
    // Common data shared by all UI implementations. UIs talk only to the vault service, never to stores or crypto.
    std::unique_ptr<VaultService> vault;
    bool isLoggedIn;
    std::string dataPath;

    // Wrap VaultService calls: log and return false/nullopt instead of throwing into UI code.
    bool safeAddCredential(const std::string& platform,
                           const std::string& username,
                           const std::string& password,
                           std::optional<CipherAlg> encryptionType);
    std::optional<Credential> safeGetCredentials(const std::string& platform);
    bool safeDeleteCredential(const std::string& platform);
    std::vector<std::string> safeGetPlatforms();
    // Validates (current right, new repeated, long enough, actually new) and changes it. false + error on failure.
    bool safeChangeMasterPassword(const std::string& current,
                                  const std::string& next,
                                  const std::string& repeat,
                                  std::string& error);
    // One line for the user: where the vault is kept and whether the ESP32 is reachable.
    std::string syncStatusText() const;

    // Hosts this device is paired with, best role first; stores owned by `vault`. Paired devices aren't vault data,
    // so the Devices screens use these directly, bypassing VaultService.
    std::vector<PairedHost> hosts_;
    EspStore* board_ = nullptr;  // the config's esp* host, null without espHost
    bool deviceOnly_ = false;    // localCopy=false: board_ is the one store, and no other host can be added
    const PairedHost* pinHost() const;  // the best dedicated host: the only kind that offers PINs (§11); may be null
    std::string hostStatusText(const PairedHost& h) const;  // "synced", "not on this network", ...
    // Pairs with one more host: "ip" (the board's ports) or "ip:port" (pairing on port+1). Blocks until it's approved
    // there (<= 90 s). false + error on failure, and nothing is saved.
    bool safeAddHost(const std::string& address, const std::string& name, const std::string& code, std::string& error);
    // PROTOCOL.md §10: deletes this device's files for the host, its cursors, and pin.json if the PIN is its.
    // revokeFirst: ask the host to revoke this device first (blocks until approved there); if that fails, nothing
    // is forgotten.
    bool safeForgetHost(std::string id, bool revokeFirst, std::string& error);  // id by value: it erases the entry

    // On failure: nullopt/false, and `error` is a sentence for the user.
    std::optional<std::vector<EspStore::Device>> safeListDevices(EspStore& host, std::string& error,
                                                                 EspStore::Storage* storage = nullptr);
    bool safeRevokeDevice(EspStore& host,
                          const std::string& name,
                          std::string& error);  // blocks until approved (≤ 1 min)
    std::optional<EspStore::PairInvite> safeOpenPairing(EspStore& host, std::string& error);  // the QR a phone scans
    static std::string lastSeenText(int64_t unixTime);                   // "seen 5 min ago"
    static std::string storageText(const EspStore::Storage& s);         // "Board storage: 12 KB of 1408 KB used ..."

    // The connector, shown on start (once per run) while an ESP32 is configured but not connected
    enum class BoardState { Connected, NotPaired, Unreachable };
    BoardState checkBoard(std::string& detail);  // at most a couple of seconds; detail: why, for the user
    void setBoardHost(const std::string& host);  // this run, and saved to the config once connected
    // Writes the pairing result where the config points (mode 600) and saves espHost. false + error on failure.
    bool savePairing(const PairedFiles& files, std::string& error);
    static std::string defaultDeviceName();  // from the hostname, e.g. "nixos"

    // PIN unlock, checked by the board (PinUnlock.h). Needs the board; the master password always works too.
    static std::string pinFilePath();  // configDir()/pin.json, this device only
    bool hasPin() const;               // set up on this device (the board may still have dropped it)
    enum class PinResult { Unlocked, Wrong, Removed, Unavailable, Failed };
    PinResult safeUnlockWithPin(const std::string& pin, std::string& message);  // message: for the user
    // Requires unlocked. Asks for the master password again: setting a PIN is as sensitive as changing it.
    bool safeSetPin(const std::string& masterPassword, const std::string& pin, const std::string& repeat, std::string& error);
    bool safeRemovePin(std::string& error);

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
                               CipherAlg encryptionType) = 0;

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
                               std::optional<CipherAlg> encryptionType = std::nullopt) = 0;

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
     * @param username Username (can be updated or unchanged)
     * @param password Password (can be updated or unchanged)
     * @param encryptionType Optional new encryption type (if not specified, preserves existing type)
     * @return True if credentials were updated successfully
     */
    virtual bool updateCredential(const std::string& platform,
                                  const std::string& username,
                                  const std::string& password,
                                  std::optional<CipherAlg> encryptionType = std::nullopt) = 0;

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
};

#endif  // UI_MANAGER_H
