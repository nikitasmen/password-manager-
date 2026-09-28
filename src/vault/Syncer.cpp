#include "Syncer.h"

#include <filesystem>
#include <fstream>

namespace {

constexpr size_t kBatch = 32;  // PROTOCOL.md §7: max records per POST /entries

struct Cursors {
    std::string vaultId;
    uint64_t localSeq = 0, remoteSeq = 0;
};

Cursors loadCursors(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    auto j = nlohmann::json::parse(in);
    return {j.value("vault_id", ""), j.value("local_seq", uint64_t{0}), j.value("remote_seq", uint64_t{0})};
}

void saveCursors(const std::string& path, const Cursors& c) {
    std::ofstream(path, std::ios::trunc)
        << nlohmann::json{{"vault_id", c.vaultId}, {"local_seq", c.localSeq}, {"remote_seq", c.remoteSeq}}.dump();
}

// Deterministic winner between two metas of the same vault: higher rev, then higher key blob.
// The tie-break matters when two devices changed the master password offline from the same rev.
bool metaWins(const VaultMeta& a, const VaultMeta& b) {
    return a.rev != b.rev ? a.rev > b.rev : a.key > b.key;
}

void push(IVaultStore& to, const std::vector<EntryRecord>& entries) {
    for (size_t i = 0; i < entries.size(); i += kBatch) {
        auto end = entries.begin() + static_cast<long>(std::min(entries.size(), i + kBatch));
        to.putEntries({entries.begin() + static_cast<long>(i), end});
    }
}

}  // namespace

Syncer::Syncer(IVaultStore& local, IVaultStore& remote, std::string statePath)
    : local_(local), remote_(remote), statePath_(std::move(statePath)) {
}

bool Syncer::sync() {
    bool localChanged = false;

    // 1. meta
    auto lm = local_.getMeta();
    auto rm = remote_.getMeta();
    if (!lm && !rm) return false;
    if (lm && rm && lm->vaultId != rm->vaultId)
        throw VaultMismatch("the ESP32 holds a different vault (vault_id " + rm->vaultId + ")");
    if (lm && (!rm || metaWins(*lm, *rm))) {
        remote_.putMeta(*lm, rm ? rm->rev : 0);  // on a CAS race, the next sync retries
    } else if (rm && (!lm || metaWins(*rm, *lm))) {
        localChanged |= local_.putMeta(*rm, lm ? lm->rev : 0);
    }

    // 2. push, 3. pull
    std::string vaultId = (lm ? lm : rm)->vaultId;
    Cursors c = loadCursors(statePath_);
    if (c.vaultId != vaultId) c = {vaultId, 0, 0};

    auto mine = local_.changesAfter(c.localSeq);
    push(remote_, mine.entries);

    auto theirs = remote_.changesAfter(c.remoteSeq);
    if (!theirs.entries.empty()) {
        local_.putEntries(theirs.entries);
        localChanged = true;
    }
    c.remoteSeq = theirs.seq;
    // Not the post-pull seq: that could skip a write another app instance made meanwhile. Pulled records are
    // echoed back once instead, which the §5 merge rule ignores (not newer).
    c.localSeq = mine.seq;
    saveCursors(statePath_, c);
    return localChanged;
}
