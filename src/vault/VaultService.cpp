#include "VaultService.h"

#include <algorithm>
#include <iostream>

namespace {
// Reads re-sync at most this often; an unreachable remote is retried no sooner than this either,
// so being away from home doesn't add a connect timeout to every click.
constexpr std::chrono::seconds kSyncMaxAge{30};
constexpr size_t kMaxRecordBytes = 12 * 1024;  // fits one POST /entries with room to spare

int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}
}  // namespace

VaultService::VaultService(std::unique_ptr<IVaultStore> local,
                           std::unique_ptr<IVaultStore> remote,
                           std::string syncStatePath)
    : local_(std::move(local)), remote_(std::move(remote)), syncStatePath_(std::move(syncStatePath)) {
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
    if (!remote_ || syncStatus_ == SyncStatus::Ok) {  // the OLED hint goes to whichever store is the board
        try {
            (remote_ ? *remote_ : *local_).noteAccess(it->second.platform, it->second.username);
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

void VaultService::changeMasterPassword(const std::string& newPassword) {
    requireUnlocked();
    VaultMeta current = *local_->getMeta();
    if (!local_->putMeta(vaultformat::rewrap(current, vaultKey_, newPassword), current.rev))
        throw std::runtime_error("the vault changed meanwhile; try again");
    sync();
}

VaultService::SyncStatus VaultService::sync() {
    if (!remote_) return syncStatus_ = SyncStatus::Disabled;
    lastSyncAttempt_ = std::chrono::steady_clock::now();
    try {
        bool changed = syncStores(*local_, *remote_, syncStatePath_);
        syncError_.clear();
        syncStatus_ = SyncStatus::Ok;
        if (changed && isUnlocked()) reindex();
    } catch (const StoreUnavailable& e) {
        syncError_ = e.what();
        syncStatus_ = SyncStatus::Offline;
    } catch (const std::exception& e) {  // VaultMismatch, bad token, ...: keep working locally, surface it
        syncError_ = e.what();
        syncStatus_ = SyncStatus::Error;
    }
    return syncStatus_;
}

void VaultService::refresh() {
    if (remote_) {
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
