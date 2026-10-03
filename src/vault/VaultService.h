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

// A host's role (docs/PROTOCOL.md §6), best first: it decides the sync order and which host gets PINs.
enum class HostRole { Dedicated, Server, Peer };
inline HostRole hostRoleOf(const std::string& wire) {  // as GET /devices says it; unknown = the least trusted
    return wire == "dedicated" ? HostRole::Dedicated : wire == "server" ? HostRole::Server : HostRole::Peer;
}
// Sync order, and which dedicated host is "the" PIN host: best role first, then by id, so it's the same on every start.
inline bool hostBefore(HostRole a, const std::string& aId, HostRole b, const std::string& bId) {
    return a != b ? a < b : aId < bId;
}
inline const char* hostRoleName(HostRole r) {
    return r == HostRole::Dedicated ? "dedicated" : r == HostRole::Server ? "server" : "peer";
}

// One host this device syncs with.
struct SyncHost {
    std::string id;  // hex SHA-256 of its pinned server cert: keys its sync cursors (PROTOCOL.md §8)
    HostRole role = HostRole::Dedicated;
    std::unique_ptr<IVaultStore> store;
};

/**
 * The one API every front end (GUI, TUI, ...) talks to. Encryption happens here, on the client;
 * stores only see ciphertext.
 *
 * With hosts (local-first): reads and writes go to the local store, so it works offline, and it syncs with
 * every host that answers, best role first, on unlock, after every write, and before reads once the last sync
 * is older than kSyncMaxAge. Being offline is normal, not an error.
 * Without hosts: the one store is read directly on every read. That's a local-only vault, or device-only
 * mode, where the ESP32 itself is the store and nothing is kept on this machine.
 */
class VaultService {
   public:
    enum class SyncStatus { Disabled, Ok, Offline, Error };

    // `hosts` may be empty (local only). `syncStatePath` is where sync cursors are kept.
    VaultService(std::unique_ptr<IVaultStore> local, std::vector<SyncHost> hosts, std::string syncStatePath);
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
    // Rewraps the vault key; entries aren't re-encrypted. false = currentPassword is wrong (nothing changed).
    bool changeMasterPassword(const std::string& currentPassword, const std::string& newPassword);
    [[nodiscard]] bool verifyMasterPassword(const std::string& password);  // requires unlocked
    // The cipher new entries get, on every device: the meta's entry_alg (PROTOCOL.md §3). Setting it syncs.
    CipherAlg entryCipher();
    void setEntryCipher(CipherAlg alg);

    // PIN unlock (PinUnlock.h): the vault key sealed under a key from the PIN and the board's secret.
    // These never see the PIN or the secret, only the derived key.
    std::string sealKeyForPin(const std::string& pinKey);  // requires unlocked; returns the blob
    bool unlockWithPinKey(const std::string& pinKey, const std::string& blob);  // false = doesn't open this vault

    // Hosts the caller just found unreachable (the connector's startup check): the next sync doesn't wait on them
    // again, even when nothing else answers, if it comes within a few seconds.
    void noteOffline(const std::vector<std::string>& ids);
    // Device-only: may the one store get access hints? Only if it's a dedicated host (the hint is in the clear).
    void setLocalAccessHints(bool on) {
        localHints_ = on;
    }
    // Pairing with another host, or forgetting one (which also drops its cursors). Not in device-only mode.
    void addHost(SyncHost host);
    void removeHost(const std::string& id);

    // Ok if any host synced, Error if none did and one failed, Offline if none answered.
    SyncStatus sync();
    // Each host's result in the last sync, in sync order (best role first).
    struct HostStatus {
        std::string id;
        HostRole role;
        SyncStatus status = SyncStatus::Disabled;  // Disabled = not tried yet
        std::string error;
        std::chrono::steady_clock::time_point triedAt{};  // last attempt; an Offline host waits kOfflineRetry
        bool justChecked = false;  // noteOffline: it didn't answer the startup check a moment ago
    };
    [[nodiscard]] const std::vector<HostStatus>& hostStatuses() const {
        return hostStatus_;
    }
    [[nodiscard]] SyncStatus lastSyncStatus() const {
        return syncStatus_;
    }
    [[nodiscard]] const std::string& lastSyncError() const {
        return syncError_;
    }

   private:
    std::string vaultId();  // of the current meta
    void requireUnlocked() const;
    void reindex();
    void refresh();  // before a read: sync if stale, or re-read the store when there is no remote
    int64_t nextTimestamp(const std::string& id) const;

    std::unique_ptr<IVaultStore> local_;
    void summarize();
    bool localHints_ = true;
    std::vector<SyncHost> hosts_;  // best role first
    std::vector<HostStatus> hostStatus_;  // parallel to hosts_
    std::string syncStatePath_;
    std::string vaultKey_;                      // empty = locked
    std::map<std::string, Credential> index_;   // entry id -> decrypted credential
    std::map<std::string, int64_t> updatedOf_;  // entry id -> record.updated, to keep timestamps increasing
    SyncStatus syncStatus_ = SyncStatus::Disabled;
    std::string syncError_;
    std::chrono::steady_clock::time_point lastSyncAttempt_{};
};

#endif  // VAULT_SERVICE_H
