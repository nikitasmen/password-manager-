#include "VaultService.h"

#include <algorithm>
#include <iostream>

namespace {
// Reads re-sync at most this often; an unreachable remote is retried no sooner than this either,
// so being away from home doesn't add a connect timeout to every click.
constexpr std::chrono::seconds kSyncMaxAge{30};
// One active host per network (PROTOCOL.md §6): most hosts are elsewhere at any moment. One that didn't answer
// is skipped this long, unless no other host syncs.
constexpr std::chrono::minutes kOfflineRetry{5};
constexpr std::chrono::seconds kJustChecked{10};  // noteOffline's answer stands this long
constexpr size_t kMaxRecordBytes = 12 * 1024;  // fits one POST /entries with room to spare

int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}
}  // namespace

VaultService::VaultService(std::unique_ptr<IVaultStore> local, std::vector<SyncHost> hosts, std::string syncStatePath)
    : local_(std::move(local)), syncStatePath_(std::move(syncStatePath)) {
    for (SyncHost& h : hosts) addHost(std::move(h));
}

void VaultService::addHost(SyncHost host) {
    auto at = std::find_if(hosts_.begin(), hosts_.end(),
                           [&](const SyncHost& h) { return hostBefore(host.role, host.id, h.role, h.id); });
    hostStatus_.insert(hostStatus_.begin() + (at - hosts_.begin()), {host.id, host.role});
    hosts_.insert(at, std::move(host));
}

void VaultService::noteOffline(const std::vector<std::string>& ids) {
    const auto now = std::chrono::steady_clock::now();
    for (HostStatus& s : hostStatus_)
        if (std::find(ids.begin(), ids.end(), s.id) != ids.end()) {
            s.status = SyncStatus::Offline;
            s.error = "not reachable";
            s.triedAt = now;
            s.justChecked = true;
        }
}

void VaultService::removeHost(const std::string& id) {
    for (size_t i = 0; i < hosts_.size(); i++)
        if (hosts_[i].id == id) {
            hosts_.erase(hosts_.begin() + i);
            hostStatus_.erase(hostStatus_.begin() + i);
            break;
        }
    if (!syncStatePath_.empty()) forgetCursors(syncStatePath_, id);
    summarize();  // forgetting the only host that synced, or the last one, changes what the status should say
}

VaultService::~VaultService() {
    lock();
}

bool VaultService::exists() {
    if (!local_->getMeta()) sync();  // a new device learns about the vault from the remote
    return local_->getMeta().has_value();
}

void VaultService::create(const std::string& masterPassword, CipherAlg alg, int kdfIterations) {
    if (exists()) throw std::runtime_error("a vault already exists");
    std::string key;
    VaultMeta meta = vaultformat::createMeta(masterPassword, alg, key, kdfIterations);
    local_->putMeta(meta, 0);
    lock();
    vaultKey_ = std::move(key);
    reindex();
    sync();
}

bool VaultService::unlock(const std::string& masterPassword) {
    sync();  // pick up password changes and entries from other devices first
    auto meta = local_->getMeta();
    if (!meta) return false;
    try {
        std::string key = vaultformat::unwrapVaultKey(masterPassword, *meta);
        lock();
        vaultKey_ = std::move(key);
    } catch (const WrongPassword&) {
        return false;
    }
    reindex();
    return true;
}

void VaultService::lock() {
    vaultcrypto::wipe(vaultKey_);
    for (auto& [id, c] : index_) vaultcrypto::wipe(c.password);
    index_.clear();
    updatedOf_.clear();
}

bool VaultService::isUnlocked() const {
    return !vaultKey_.empty();
}

void VaultService::requireUnlocked() const {
    if (!isUnlocked()) throw std::logic_error("vault is locked");
}

void VaultService::reindex() {
    for (auto& [id, c] : index_) vaultcrypto::wipe(c.password);
    index_.clear();
    updatedOf_.clear();
    for (const EntryRecord& rec : local_->changesAfter(0).entries) {
        updatedOf_[rec.id] = rec.updated;
        try {
            if (auto cred = vaultformat::openEntry(vaultKey_, rec)) index_[rec.id] = std::move(*cred);
        } catch (const std::exception& e) {  // one corrupt/tampered record must not lock you out of the rest
            std::cerr << "skipping unreadable entry " << rec.id << ": " << e.what() << "\n";
        }
    }
}

std::vector<std::string> VaultService::platforms() {
    requireUnlocked();
    refresh();
    std::vector<std::string> out;
    for (const auto& [id, c] : index_) out.push_back(c.platform);
    std::sort(out.begin(), out.end());
    return out;
}

std::optional<Credential> VaultService::get(const std::string& platform) {
    requireUnlocked();
    refresh();
    auto it = index_.find(vaultformat::entryId(vaultKey_, platform));
    if (it == index_.end()) return std::nullopt;
    // The OLED hint goes to the best dedicated host that answered (device-only: the one store, if it's one). It's in
    // the clear, and only the board shows it: a server or peer host never gets it (PROTOCOL.md §7, §12).
    IVaultStore* shown = hosts_.empty() && localHints_ ? local_.get() : nullptr;
    for (size_t i = 0; i < hosts_.size() && !shown; i++)
        if (hostStatus_[i].status == SyncStatus::Ok && hosts_[i].role == HostRole::Dedicated)
            shown = hosts_[i].store.get();
    if (shown) {
        try {
            shown->noteAccess(it->second.platform, it->second.username);
        } catch (const std::exception&) {  // purely informational; never block a read on it
        }
    }
    return it->second;
}

int64_t VaultService::nextTimestamp(const std::string& id) const {
    auto it = updatedOf_.find(id);
    return std::max(nowMs(), it == updatedOf_.end() ? 0 : it->second + 1);  // strictly newer than what we have
}

void VaultService::put(const Credential& cred) {
    requireUnlocked();
    if (cred.platform.empty() || cred.username.empty() || cred.password.empty())
        throw std::invalid_argument("platform, username and password are all required");
    std::string id = vaultformat::entryId(vaultKey_, cred.platform);
    EntryRecord rec = vaultformat::sealEntry(vaultKey_, cred, nextTimestamp(id));
    // A record the ESP32 can't accept (16 KB per request) would block sync forever; refuse it up front.
    if (nlohmann::json(rec).dump().size() > kMaxRecordBytes)
        throw std::invalid_argument("entry too large (keep platform, username and password under ~8 KB)");
    local_->putEntries({rec});
    reindex();
    sync();
}

bool VaultService::remove(const std::string& platform) {
    requireUnlocked();
    std::string id = vaultformat::entryId(vaultKey_, platform);
    if (!index_.count(id)) return false;
    local_->putEntries({vaultformat::tombstone(id, nextTimestamp(id))});
    reindex();
    sync();
    return true;
}

bool VaultService::changeMasterPassword(const std::string& currentPassword, const std::string& newPassword) {
    requireUnlocked();
    if (!verifyMasterPassword(currentPassword)) return false;  // being unlocked isn't enough: they must know it
    VaultMeta current = *local_->getMeta();
    if (!local_->putMeta(vaultformat::rewrap(current, vaultKey_, newPassword), current.rev))
        throw std::runtime_error("the vault changed meanwhile; try again");
    sync();
    return true;
}

bool VaultService::verifyMasterPassword(const std::string& password) {
    requireUnlocked();
    try {
        std::string key = vaultformat::unwrapVaultKey(password, *local_->getMeta());
        const bool same = key == vaultKey_;
        vaultcrypto::wipe(key);
        return same;
    } catch (const WrongPassword&) {
        return false;
    }
}

namespace {
const std::string kPinAad = "pwvault-pin:";  // + vault id: a PIN blob opens only the vault it was made for
}

std::string VaultService::vaultId() {
    auto meta = local_->getMeta();
    if (!meta) throw std::runtime_error("no vault yet");
    return meta->vaultId;
}

std::string VaultService::sealKeyForPin(const std::string& pinKey) {
    requireUnlocked();
    return makeCipher(CipherAlg::Aes256Gcm)->seal(pinKey, vaultKey_, kPinAad + vaultId());
}

bool VaultService::unlockWithPinKey(const std::string& pinKey, const std::string& blob) {
    sync();  // like unlock(): pick up entries from other devices first
    auto meta = local_->getMeta();
    if (!meta) return false;
    try {
        std::string key = makeCipher(CipherAlg::Aes256Gcm)->open(pinKey, blob, kPinAad + meta->vaultId);
        lock();
        vaultKey_ = std::move(key);
    } catch (const DecryptError&) {
        return false;
    }
    reindex();
    return true;
}

// PROTOCOL.md §8, several hosts: each in turn, with its own cursors. A change pulled from one host is pushed to
// the hosts after it in this round, and to the ones before it in the next.
VaultService::SyncStatus VaultService::sync() {
    if (hosts_.empty()) return syncStatus_ = SyncStatus::Disabled;
    const auto now = lastSyncAttempt_ = std::chrono::steady_clock::now();
    bool changed = false;
    auto syncWith = [&](size_t i) {
        HostStatus& s = hostStatus_[i];
        s.triedAt = now;
        s.justChecked = false;
        try {
            changed |= syncStores(*local_, *hosts_[i].store, syncStatePath_, hosts_[i].id);
            s.status = SyncStatus::Ok;
            s.error.clear();
        } catch (const StoreUnavailable& e) {
            s.status = SyncStatus::Offline;
            s.error = e.what();
        } catch (const std::exception& e) {  // VaultMismatch, a revoked cert, ...: keep working locally, surface it
            s.status = SyncStatus::Error;
            s.error = e.what();
        }
    };
    std::vector<size_t> away;  // offline a moment ago: probably on another network
    for (size_t i = 0; i < hosts_.size(); i++) {
        const HostStatus& s = hostStatus_[i];
        if (s.status == SyncStatus::Offline && now - s.triedAt < kOfflineRetry) away.push_back(i);
        else syncWith(i);
    }
    auto none = [&] {
        return std::none_of(
            hostStatus_.begin(), hostStatus_.end(), [](const HostStatus& s) { return s.status == SyncStatus::Ok; });
    };
    for (size_t i : away)  // nothing else answered: maybe we just came back to its network (unless it was just checked)
        if (none() && !(hostStatus_[i].justChecked && now - hostStatus_[i].triedAt < kJustChecked)) syncWith(i);
    if (changed && isUnlocked()) reindex();
    summarize();
    return syncStatus_;
}

// What the hosts' last results add up to: Ok if any synced, Error if none did and one failed, else Offline.
void VaultService::summarize() {
    if (hosts_.empty()) {
        syncStatus_ = SyncStatus::Disabled;
        syncError_.clear();
        return;
    }
    auto first = [&](SyncStatus st) {
        return std::find_if(
            hostStatus_.begin(), hostStatus_.end(), [&](const HostStatus& s) { return s.status == st; });
    };
    if (first(SyncStatus::Ok) != hostStatus_.end()) {
        syncStatus_ = SyncStatus::Ok;
        syncError_.clear();
    } else if (auto e = first(SyncStatus::Error); e != hostStatus_.end()) {
        syncStatus_ = SyncStatus::Error;
        syncError_ = e->error;
    } else {
        syncStatus_ = SyncStatus::Offline;
        syncError_ = hostStatus_.front().error;
    }
}

void VaultService::refresh() {
    if (!hosts_.empty()) {
        if (std::chrono::steady_clock::now() - lastSyncAttempt_ > kSyncMaxAge) sync();
        return;
    }
    // No remote: the store itself is the source (a local-only file, or the ESP32 in device-only mode),
    // so every read re-reads it. That keeps device-only truthful: each read reaches the board.
    try {
        reindex();
        syncStatus_ = SyncStatus::Disabled;
    } catch (const StoreUnavailable& e) {
        syncError_ = e.what();
        syncStatus_ = SyncStatus::Offline;
        throw;
    }
}
