#include "VaultFormat.h"

#include <algorithm>
#include <cctype>

#include "../core/base64.h"

namespace {
const char* kKeyAad = "pwvault/v1/key";

CipherAlg algOf(const std::string& name) {
    auto alg = cipherFromName(name);
    if (!alg) throw std::runtime_error("unsupported cipher: " + name);
    return *alg;
}
}  // namespace

void to_json(nlohmann::json& j, const VaultMeta& m) {
    j = {{"v", m.v},       {"vault_id", m.vaultId}, {"rev", m.rev}, {"kdf", m.kdf},
         {"iter", m.iter}, {"salt", m.salt},        {"alg", m.alg}, {"key", m.key}};
    if (!m.entryAlg.empty()) j["entry_alg"] = m.entryAlg;
}

void from_json(const nlohmann::json& j, VaultMeta& m) {
    j.at("v").get_to(m.v);
    j.at("vault_id").get_to(m.vaultId);
    j.at("rev").get_to(m.rev);
    j.at("kdf").get_to(m.kdf);
    j.at("iter").get_to(m.iter);
    j.at("salt").get_to(m.salt);
    j.at("alg").get_to(m.alg);
    j.at("key").get_to(m.key);
    m.entryAlg = j.value("entry_alg", "");
}

void to_json(nlohmann::json& j, const EntryRecord& e) {
    j = {{"id", e.id}, {"updated", e.updated}, {"deleted", e.deleted}, {"alg", e.alg}, {"data", e.data}, {"seq", e.seq}};
}

void from_json(const nlohmann::json& j, EntryRecord& e) {
    j.at("id").get_to(e.id);
    j.at("updated").get_to(e.updated);
    j.at("deleted").get_to(e.deleted);
    j.at("alg").get_to(e.alg);
    j.at("data").get_to(e.data);
    e.seq = j.value("seq", uint64_t{0});
}

namespace vaultformat {

bool isNewer(const EntryRecord& in, const EntryRecord& cur) {
    if (in.updated != cur.updated) return in.updated > cur.updated;
    return in.data > cur.data;  // std::string compares bytes (as unsigned char), like PROTOCOL.md §5
}

VaultMeta createMeta(const std::string& password, CipherAlg alg, std::string& vaultKey, int iterations) {
    VaultMeta m;
    m.vaultId = vaultcrypto::toHex(vaultcrypto::randomBytes(16));
    m.iter = iterations;
    m.salt = base64::encode(vaultcrypto::randomBytes(16));
    m.alg = cipherName(alg);
    vaultKey = vaultcrypto::randomBytes(32);
    std::string kek = deriveKek(password, m);
    m.key = makeCipher(alg)->seal(kek, vaultKey, kKeyAad);
    vaultcrypto::wipe(kek);
    return m;
}

std::string deriveKek(const std::string& password, const VaultMeta& meta) {
    if (meta.kdf != "pbkdf2-sha256") throw std::runtime_error("unsupported kdf: " + meta.kdf);
    return vaultcrypto::pbkdf2Sha256(password, base64::decode(meta.salt), meta.iter);
}

std::string unwrapVaultKey(const std::string& password, const VaultMeta& meta) {
    std::string kek = deriveKek(password, meta);
    try {
        std::string key = makeCipher(algOf(meta.alg))->open(kek, meta.key, kKeyAad);
        vaultcrypto::wipe(kek);
        return key;
    } catch (const DecryptError&) {
        vaultcrypto::wipe(kek);
        throw WrongPassword();
    }
}

VaultMeta rewrap(const VaultMeta& meta, const std::string& vaultKey, const std::string& newPassword) {
    VaultMeta m = meta;
    m.rev = meta.rev + 1;
    m.salt = base64::encode(vaultcrypto::randomBytes(16));
    std::string kek = deriveKek(newPassword, m);
    m.key = makeCipher(algOf(m.alg))->seal(kek, vaultKey, kKeyAad);
    vaultcrypto::wipe(kek);
    return m;
}

std::string entryId(const std::string& vaultKey, const std::string& platform) {
    std::string lower = platform;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
    return vaultcrypto::toHex(vaultcrypto::hmacSha256(vaultKey, lower).substr(0, 16));
}

std::string entryAad(const std::string& id) {
    return "pwvault/v1/entry/" + id;
}

EntryRecord sealEntry(const std::string& vaultKey, const Credential& cred, int64_t updated) {
    EntryRecord e;
    e.id = entryId(vaultKey, cred.platform);
    e.updated = updated;
    e.alg = cipherName(cred.alg);
    // ordered_json keeps platform, username, password order, matching the reference implementation byte for byte
    std::string plain =
        nlohmann::ordered_json{{"platform", cred.platform}, {"username", cred.username}, {"password", cred.password}}
            .dump();
    e.data = makeCipher(cred.alg)->seal(vaultKey, plain, entryAad(e.id));
    vaultcrypto::wipe(plain);
    return e;
}

EntryRecord tombstone(const std::string& id, int64_t updated) {
    EntryRecord e;
    e.id = id;
    e.updated = updated;
    e.deleted = true;
    e.alg = cipherName(CipherAlg::Aes256Gcm);
    return e;
}

std::optional<Credential> openEntry(const std::string& vaultKey, const EntryRecord& rec) {
    if (rec.deleted) return std::nullopt;
    CipherAlg alg = algOf(rec.alg);
    std::string plain = makeCipher(alg)->open(vaultKey, rec.data, entryAad(rec.id));
    auto j = nlohmann::json::parse(plain);
    vaultcrypto::wipe(plain);
    return Credential{j.at("platform"), j.at("username"), j.at("password"), alg};
}

}  // namespace vaultformat
