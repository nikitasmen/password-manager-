#ifndef LOCAL_FILE_STORE_H
#define LOCAL_FILE_STORE_H

#include <nlohmann/json.hpp>
#include <string>

#include "IVaultStore.h"

// One JSON file: {"meta": {...}, "seq": N, "entries": {id: record}}.
// Re-read on every call so several app instances (GUI + TUI) can share it.
class LocalFileStore : public IVaultStore {
   public:
    explicit LocalFileStore(std::string path);

    std::optional<VaultMeta> getMeta() override;
    bool putMeta(const VaultMeta& meta, int ifRev) override;
    Changes changesAfter(uint64_t seq) override;
    void putEntries(const std::vector<EntryRecord>& entries) override;

   private:
    nlohmann::json load() const;
    void save(const nlohmann::json& doc) const;  // write temp file + rename, so a crash never leaves half a vault

    std::string path_;
};

#endif  // LOCAL_FILE_STORE_H
