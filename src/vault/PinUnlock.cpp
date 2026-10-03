#include "PinUnlock.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#include "Crypto.h"

bool validPin(const std::string& pin) {
    return pin.size() >= 4 && pin.size() <= 32 &&
           std::all_of(pin.begin(), pin.end(), [](unsigned char c) { return std::isdigit(c); });
}

std::optional<PinFile> loadPinFile(const std::string& path) {
    std::ifstream in(path);
    nlohmann::json j = nlohmann::json::parse(in, nullptr, false);
    if (!in || !j.is_object()) return std::nullopt;
    try {
        return PinFile{j.at("salt"), j.at("iter"), j.at("blob"), j.value("host", "")};
    } catch (const nlohmann::json::exception&) {
        return std::nullopt;
    }
}

std::string readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}

void writePrivateTmp(const std::string& path, const std::string& content) {
    namespace fs = std::filesystem;
    const std::string tmp = path + ".tmp";
    fs::create_directories(fs::path(tmp).parent_path());
    { std::ofstream(tmp, std::ios::trunc); }  // create it empty, restrict it, then write
    fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
    std::ofstream out(tmp, std::ios::trunc | std::ios::binary);
    out << content;
    out.close();
    if (!out) throw std::runtime_error("couldn't write " + tmp);
}

void savePinFile(const std::string& path, const PinFile& f) {
    nlohmann::json j{{"salt", f.salt}, {"iter", f.iterations}, {"blob", f.blob}};
    if (!f.host.empty()) j["host"] = f.host;
    writePrivateTmp(path, j.dump());
    std::filesystem::rename(path + ".tmp", path);
}

std::string pinProofHex(const std::string& pin, const std::string& saltRaw, int iterations) {
    std::string k = vaultcrypto::pbkdf2Sha256(pin, saltRaw, iterations);
    std::string hex = vaultcrypto::toHex(k);
    vaultcrypto::wipe(k);
    return hex;
}

std::string pinWrapKey(const std::string& secretHex, const std::string& proofHex) {
    return vaultcrypto::hmacSha256(secretHex, "pwvault-pin-key\n" + proofHex);
}
