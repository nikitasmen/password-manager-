#include "Syncer.h"

#include <filesystem>
#include <fstream>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace {

// PROTOCOL.md §7: at most 32 records and 16 KB per POST /entries; keep headroom for the {"entries":[...]} wrapper
constexpr size_t kBatchCount = 32, kBatchBytes = 12 * 1024;

struct Cursors {
    std::string vaultId;
    uint64_t localSeq = 0, remoteSeq = 0;
};

// {"vault_id":…,"hosts":{"<host id>":{"local_seq":L,"remote_seq":R}}}. A missing or corrupt file, or a host
// missing from it, just means "sync everything" with that host, which the merge rule makes harmless. The v1
// file ({"vault_id","local_seq","remote_seq"}) has no "hosts", so it reads as that too.
nlohmann::json loadState(const std::string& path) {
    std::ifstream in(path);
    auto j = nlohmann::json::parse(in, nullptr, /*allow_exceptions=*/false);
    return j.is_object() ? j : nlohmann::json::object();
}

Cursors cursorsOf(const nlohmann::json& state, const std::string& hostId) {
    auto hosts = state.find("hosts");
    if (hosts == state.end() || !hosts->is_object() || !hosts->contains(hostId)) return {state.value("vault_id", "")};
    const auto& h = (*hosts)[hostId];
    if (!h.is_object()) return {state.value("vault_id", "")};
    return {state.value("vault_id", ""), h.value("local_seq", uint64_t{0}), h.value("remote_seq", uint64_t{0})};
}

// The whole read-modify-write of sync.json: the app and `--serve` on one machine share it (PROTOCOL.md §8).
class StateLock {
   public:
    explicit StateLock(const std::string& path) {
#ifndef _WIN32
        fd_ = ::open((path + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd_ < 0 || ::flock(fd_, LOCK_EX) != 0) throw std::runtime_error("cannot lock " + path + ".lock");
#endif  // ponytail: no lock on Windows, where --serve doesn't exist and one app instance writes it
    }
    ~StateLock() {
#ifndef _WIN32
        if (fd_ >= 0) ::close(fd_);
#endif
    }
    StateLock(const StateLock&) = delete;
    StateLock& operator=(const StateLock&) = delete;

   private:
    int fd_ = -1;
};

void writeState(const std::string& path, const nlohmann::json& state) {
    std::string tmp = path + ".tmp";  // temp + rename: never a half-written file (writers take StateLock first)
    {
        std::ofstream out(tmp, std::ios::trunc);
        out << state.dump();
        if (!out.flush()) throw std::runtime_error("cannot write " + tmp);
    }
    std::filesystem::rename(tmp, path);
}

// Re-reads the file so another host's cursors, saved meanwhile, survive. Another vault's cursors don't.
void saveCursors(const std::string& path, const std::string& hostId, const Cursors& c) {
    StateLock lock(path);
    nlohmann::json state = loadState(path);
    if (state.value("vault_id", "") != c.vaultId || !state.contains("hosts") || !state["hosts"].is_object())
        state = {{"vault_id", c.vaultId}, {"hosts", nlohmann::json::object()}};
    state["hosts"][hostId] = {{"local_seq", c.localSeq}, {"remote_seq", c.remoteSeq}};
    writeState(path, state);
}

// Deterministic winner between two metas of the same vault: higher rev, then higher key blob, then entry_alg.
// The tie-break matters when two devices changed the master password or the cipher offline from the same rev.
bool metaWins(const VaultMeta& a, const VaultMeta& b) {
    if (a.rev != b.rev) return a.rev > b.rev;
    return a.key != b.key ? a.key > b.key : a.entryAlg > b.entryAlg;
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

void forgetCursors(const std::string& statePath, const std::string& hostId) {
    StateLock lock(statePath);
    nlohmann::json state = loadState(statePath);
    if (state.contains("hosts") && state["hosts"].is_object() && state["hosts"].erase(hostId))
        writeState(statePath, state);
}

bool syncStores(IVaultStore& local, IVaultStore& remote, const std::string& statePath, const std::string& hostId) {
    bool localChanged = false;

    // 1. meta
    auto lm = local.getMeta();
    auto rm = remote.getMeta();
    if (!lm && !rm) return false;
    if (lm && rm && lm->vaultId != rm->vaultId)
        throw VaultMismatch("the host holds a different vault (vault_id " + rm->vaultId + ")");
    if (lm && (!rm || metaWins(*lm, *rm))) {
        remote.putMeta(*lm, rm ? rm->rev : 0);  // on a CAS race, the next sync retries
    } else if (rm && (!lm || metaWins(*rm, *lm))) {
        localChanged |= local.putMeta(*rm, lm ? lm->rev : 0);
    }

    // 2. push, 3. pull
    std::string vaultId = (lm ? lm : rm)->vaultId;
    Cursors c = cursorsOf(loadState(statePath), hostId);
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
    saveCursors(statePath, hostId, c);
    return localChanged;
}
