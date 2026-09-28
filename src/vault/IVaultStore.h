#ifndef I_VAULT_STORE_H
#define I_VAULT_STORE_H

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "VaultFormat.h"

// The store can't be reached right now (network down, board off). Callers treat this as "offline", not as an error.
class StoreUnavailable : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
};

/**
 * Where encrypted records live: docs/PROTOCOL.md §6. Stores only ever see ciphertext.
 * Implementations: LocalFileStore (disk), EspStore (the ESP32 over HTTPS).
 */
class IVaultStore {
   public:
    struct Changes {
        std::vector<EntryRecord> entries;
        uint64_t seq = 0;  // the store's current seq
    };

    virtual ~IVaultStore() = default;
    virtual std::optional<VaultMeta> getMeta() = 0;
    // Compare-and-swap on rev (0 = no meta yet). Returns false on conflict.
    virtual bool putMeta(const VaultMeta& meta, int ifRev) = 0;
    virtual Changes changesAfter(uint64_t seq) = 0;
    // Applies the §5 merge rule to each record.
    virtual void putEntries(const std::vector<EntryRecord>& entries) = 0;
    // Display-only audit hint; stores without a display ignore it.
    virtual void noteAccess(const std::string& /*platform*/, const std::string& /*username*/) {
    }
};

#endif  // I_VAULT_STORE_H
