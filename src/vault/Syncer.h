#ifndef SYNCER_H
#define SYNCER_H

#include <string>

#include "IVaultStore.h"

// Local and remote hold different vaults (different vault_id). Never merged automatically.
class VaultMismatch : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
};

/**
 * Two-way sync between any two stores: docs/PROTOCOL.md §8.
 * Remembers its cursors in a small JSON file next to the local vault.
 */
class Syncer {
   public:
    Syncer(IVaultStore& local, IVaultStore& remote, std::string statePath);
    // Throws StoreUnavailable if the remote is unreachable, VaultMismatch for a different vault.
    // Returns true if anything changed locally (caller should re-read).
    bool sync();

   private:
    IVaultStore& local_;
    IVaultStore& remote_;
    std::string statePath_;
};

#endif  // SYNCER_H
