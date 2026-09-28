#ifndef VAULT_SERVICE_H
#define VAULT_SERVICE_H

#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "IVaultStore.h"
#include "Syncer.h"

/**
 * The one API every front end (GUI, TUI, ...) talks to. Encryption happens here, on the client;
 * stores only see ciphertext.
 *
 * With a remote (local-first): reads and writes go to the local store, so it works offline, and it syncs
 * with the remote (the ESP32) on unlock, after every write, and before reads once the last sync is older
 * than kSyncMaxAge. Being offline is normal, not an error.
 * Without a remote: the one store is read directly on every read. That's a local-only vault, or device-only
 * mode, where the ESP32 itself is the store and nothing is kept on this machine.
 */
class VaultService {
   public:
    enum class SyncStatus { Disabled, Ok, Offline, Error };

    // `remote` may be null (local only). `syncStatePath` is where sync cursors are kept.
    VaultService(std::unique_ptr<IVaultStore> local, std::unique_ptr<IVaultStore> remote, std::string syncStatePath);
    ~VaultService();
    VaultService(const VaultService&) = delete;
    VaultService& operator=(const VaultService&) = delete;

    // Does a vault exist (locally, or on the remote)?
    bool exists();
    void create(const std::string& masterPassword,
                CipherAlg alg = CipherAlg::Aes256Gcm,
                int kdfIterations = kDefaultKdfIterations);
    bool unlock(const std::string& masterPassword);  // false = wrong password
    void lock();
    [[nodiscard]] bool isUnlocked() const;

    // All of these require isUnlocked().
    std::vector<std::string> platforms();
    std::optional<Credential> get(const std::string& platform);  // also tells the remote (OLED) who read what
    void put(const Credential& cred);                            // add or update
    bool remove(const std::string& platform);
    void changeMasterPassword(const std::string& newPassword);

    SyncStatus sync();
    [[nodiscard]] SyncStatus lastSyncStatus() const {
        return syncStatus_;
    }
    [[nodiscard]] const std::string& lastSyncError() const {
        return syncError_;
    }

   private:
    void requireUnlocked() const;
    void reindex();
    void refresh();  // before a read: sync if stale, or re-read the store when there is no remote
    int64_t nextTimestamp(const std::string& id) const;

    std::unique_ptr<IVaultStore> local_;
    std::unique_ptr<IVaultStore> remote_;
    std::string syncStatePath_;
    std::string vaultKey_;                      // empty = locked
    std::map<std::string, Credential> index_;   // entry id -> decrypted credential
    std::map<std::string, int64_t> updatedOf_;  // entry id -> record.updated, to keep timestamps increasing
    SyncStatus syncStatus_ = SyncStatus::Disabled;
    std::string syncError_;
    std::chrono::steady_clock::time_point lastSyncAttempt_{};
};

#endif  // VAULT_SERVICE_H
