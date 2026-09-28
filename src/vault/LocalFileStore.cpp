#include "LocalFileStore.h"

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

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
