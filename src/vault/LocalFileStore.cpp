#include "LocalFileStore.h"

#include <filesystem>
#include <fstream>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace {
// Exclusive lock around a read-modify-write, so two app instances (GUI + TUI) can't lose each other's writes.
// Readers need none: save() replaces the file atomically.
class WriteLock {
   public:
    explicit WriteLock(const std::string& path) {
#ifndef _WIN32
        fs::path lock(path + ".lock");
        if (lock.has_parent_path()) fs::create_directories(lock.parent_path());
        fd_ = ::open(lock.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd_ < 0 || ::flock(fd_, LOCK_EX) != 0) throw std::runtime_error("cannot lock " + lock.string());
#endif  // ponytail: no cross-process lock on Windows; add LockFileEx if it ever runs there with two instances
    }
    ~WriteLock() {
#ifndef _WIN32
        if (fd_ >= 0) ::close(fd_);  // closing releases the flock
#endif
    }
    WriteLock(const WriteLock&) = delete;
    WriteLock& operator=(const WriteLock&) = delete;

   private:
    int fd_ = -1;
};
}  // namespace

LocalFileStore::LocalFileStore(std::string path) : path_(std::move(path)) {
}

nlohmann::json LocalFileStore::load() const {
    std::ifstream in(path_);
    if (!in) return {{"seq", 0}, {"entries", nlohmann::json::object()}};
    return nlohmann::json::parse(in);
}

void LocalFileStore::save(const nlohmann::json& doc) const {
    fs::path target(path_);
    if (target.has_parent_path()) fs::create_directories(target.parent_path());
    fs::path tmp = target;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        out << doc.dump(1);
        if (!out.flush()) throw std::runtime_error("cannot write " + tmp.string());
    }
    fs::rename(tmp, target);
}

std::optional<VaultMeta> LocalFileStore::getMeta() {
    auto doc = load();
    if (!doc.contains("meta")) return std::nullopt;
    return doc["meta"].get<VaultMeta>();
}

bool LocalFileStore::putMeta(const VaultMeta& meta, int ifRev) {
    WriteLock lock(path_);
    auto doc = load();
    int current = doc.contains("meta") ? doc["meta"]["rev"].get<int>() : 0;
    if (current != ifRev) return false;
    doc["meta"] = meta;
    save(doc);
    return true;
}

IVaultStore::Changes LocalFileStore::changesAfter(uint64_t seq) {
    auto doc = load();
    Changes c;
    c.seq = doc["seq"].get<uint64_t>();
    for (const auto& [id, rec] : doc["entries"].items()) {
        auto e = rec.get<EntryRecord>();
        if (e.seq > seq) c.entries.push_back(std::move(e));
    }
    return c;
}

void LocalFileStore::putEntries(const std::vector<EntryRecord>& entries) {
    WriteLock lock(path_);
    auto doc = load();
    auto seq = doc["seq"].get<uint64_t>();
    bool changed = false;
    for (EntryRecord e : entries) {
        auto& slot = doc["entries"][e.id];
        if (!slot.is_null() && !vaultformat::isNewer(e, slot.get<EntryRecord>())) continue;
        e.seq = ++seq;
        slot = e;
        changed = true;
    }
    if (!changed) return;
    doc["seq"] = seq;
    save(doc);
}
