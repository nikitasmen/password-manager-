#ifndef VAULT_FORMAT_H
#define VAULT_FORMAT_H

// docs/PROTOCOL.md §1–5 in C++: the data types every store and client shares, and the pure
// functions that encrypt/decrypt them. No I/O here.

#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

#include "Crypto.h"

constexpr int kDefaultKdfIterations = 600000;

struct VaultMeta {
    int v = 1;
    std::string vaultId;
    int rev = 1;
    std::string kdf = "pbkdf2-sha256";
    int iter = kDefaultKdfIterations;
    std::string salt;  // base64
    std::string alg;   // cipher of `key`
    std::string key;   // AEAD blob of the vault key
};

struct EntryRecord {
    std::string id;
    int64_t updated = 0;
    bool deleted = false;
    std::string alg;
    std::string data;  // AEAD blob, "" for tombstones
    uint64_t seq = 0;  // assigned by the store that holds it
};

struct Credential {
    std::string platform;
    std::string username;
    std::string password;
    CipherAlg alg = CipherAlg::Aes256Gcm;
};

// Thrown by unwrapVaultKey() for a wrong master password.
class WrongPassword : public std::runtime_error {
   public:
    WrongPassword() : std::runtime_error("wrong master password") {
    }
};

void to_json(nlohmann::json& j, const VaultMeta& m);
void from_json(const nlohmann::json& j, VaultMeta& m);
void to_json(nlohmann::json& j, const EntryRecord& e);
void from_json(const nlohmann::json& j, EntryRecord& e);

namespace vaultformat {

// §5: does `in` replace `cur`?
bool isNewer(const EntryRecord& in, const EntryRecord& cur);

// §3. Returns the new meta; writes the fresh random vault key to `vaultKey`.
VaultMeta createMeta(const std::string& password,
                     CipherAlg alg,
                     std::string& vaultKey,
                     int iterations = kDefaultKdfIterations);
std::string deriveKek(const std::string& password, const VaultMeta& meta);
std::string unwrapVaultKey(const std::string& password, const VaultMeta& meta);  // throws WrongPassword
VaultMeta rewrap(const VaultMeta& meta, const std::string& vaultKey, const std::string& newPassword);

// §4
std::string entryId(const std::string& vaultKey, const std::string& platform);
std::string entryAad(const std::string& id);
EntryRecord sealEntry(const std::string& vaultKey, const Credential& cred, int64_t updated);
EntryRecord tombstone(const std::string& id, int64_t updated);
std::optional<Credential> openEntry(const std::string& vaultKey, const EntryRecord& rec);  // nullopt = tombstone

}  // namespace vaultformat

#endif  // VAULT_FORMAT_H
