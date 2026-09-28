#include "Syncer.h"

#include <filesystem>
#include <fstream>

namespace {

// PROTOCOL.md §7: at most 32 records and 16 KB per POST /entries; keep headroom for the {"entries":[...]} wrapper
constexpr size_t kBatchCount = 32, kBatchBytes = 12 * 1024;

struct Cursors {
    std::string vaultId;
    uint64_t localSeq = 0, remoteSeq = 0;
};

// A missing or corrupt file just means "sync everything", which the merge rule makes harmless.
Cursors loadCursors(const std::string& path) {
    std::ifstream in(path);
    auto j = nlohmann::json::parse(in, nullptr, /*allow_exceptions=*/false);
    if (!j.is_object()) return {};
    return {j.value("vault_id", ""), j.value("local_seq", uint64_t{0}), j.value("remote_seq", uint64_t{0})};
}

void saveCursors(const std::string& path, const Cursors& c) {  // temp + rename: never a half-written file
    std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        out << nlohmann::json{{"vault_id", c.vaultId}, {"local_seq", c.localSeq}, {"remote_seq", c.remoteSeq}}.dump();
        if (!out.flush()) throw std::runtime_error("cannot write " + tmp);
    }
    std::filesystem::rename(tmp, path);
}

// Deterministic winner between two metas of the same vault: higher rev, then higher key blob.
// The tie-break matters when two devices changed the master password offline from the same rev.
bool metaWins(const VaultMeta& a, const VaultMeta& b) {
    return a.rev != b.rev ? a.rev > b.rev : a.key > b.key;
}

void push(IVaultStore& to, const std::vector<EntryRecord>& entries) {
    std::vector<EntryRecord> batch;
    size_t bytes = 0;
    for (const EntryRecord& e : entries) {
        size_t size = nlohmann::json(e).dump().size() + 1;
        if (!batch.empty() && (batch.size() == kBatchCount || bytes + size > kBatchBytes)) {
            to.putEntries(batch);
            batch.clear();
            bytes = 0;
        }
        batch.push_back(e);
        bytes += size;
    }
    if (!batch.empty()) to.putEntries(batch);
}

}  // namespace

bool syncStores(IVaultStore& local, IVaultStore& remote, const std::string& statePath) {
    bool localChanged = false;

    // 1. meta
    auto lm = local.getMeta();
    auto rm = remote.getMeta();
    if (!lm && !rm) return false;
    if (lm && rm && lm->vaultId != rm->vaultId)
        throw VaultMismatch("the ESP32 holds a different vault (vault_id " + rm->vaultId + ")");
    if (lm && (!rm || metaWins(*lm, *rm))) {
        remote.putMeta(*lm, rm ? rm->rev : 0);  // on a CAS race, the next sync retries
    } else if (rm && (!lm || metaWins(*rm, *lm))) {
        localChanged |= local.putMeta(*rm, lm ? lm->rev : 0);
    }

    // 2. push, 3. pull
    std::string vaultId = (lm ? lm : rm)->vaultId;
    Cursors c = loadCursors(statePath);
    // A side that had no vault before this sync (wiped/new board, deleted vault.json) has none of the
    // other side's history: sync everything, not just what changed since the cursors.
    if (c.vaultId != vaultId || !lm || !rm) c = {vaultId, 0, 0};

    auto theirs = remote.changesAfter(c.remoteSeq);
    auto mine = local.changesAfter(c.localSeq);
    if (theirs.seq < c.remoteSeq || mine.seq < c.localSeq) {  // a store's history restarted (restored backup, ...)
        c = {vaultId, 0, 0};
        theirs = remote.changesAfter(0);
        mine = local.changesAfter(0);
    }
    push(remote, mine.entries);

    if (!theirs.entries.empty()) {
        local.putEntries(theirs.entries);
        localChanged = true;
    }
    c.remoteSeq = theirs.seq;
    // Not the post-pull seq: that could skip a write another app instance made meanwhile. Pulled records are
    // echoed back once instead, which the §5 merge rule ignores (not newer).
    c.localSeq = mine.seq;
    saveCursors(statePath, c);
    return localChanged;
}
