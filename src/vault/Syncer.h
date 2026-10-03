#ifndef SYNCER_H
#define SYNCER_H

#include <string>

#include "IVaultStore.h"

// Local and remote hold different vaults (different vault_id). Never merged automatically.
class VaultMismatch : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
};

// Two-way sync between any two stores: docs/PROTOCOL.md §8. Cursors live in the JSON file at `statePath`, one pair
// per host, under `hostId` (the hex SHA-256 of the host's server cert).
// Throws StoreUnavailable if the remote is unreachable, VaultMismatch for a different vault.
// Returns true if anything changed locally (caller should re-read).
bool syncStores(IVaultStore& local, IVaultStore& remote, const std::string& statePath, const std::string& hostId);

#endif  // SYNCER_H
