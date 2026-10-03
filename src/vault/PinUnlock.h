#ifndef PIN_UNLOCK_H
#define PIN_UNLOCK_H

#include <optional>
#include <string>
#include <vector>

// PIN unlock, this device's half (the board's half and the scheme: header comment of esp32/vault/vault.ino).
// This device keeps the vault key wrapped with HMAC(board secret, proof), proof = PBKDF2(PIN, salt). The board
// releases the secret only for the right proof and deletes it after 5 wrong ones, so a PIN can't be guessed
// offline from this file. The master password stays the real key.

bool validPin(const std::string& pin);  // at least 4 digits, digits only

struct PinFile {
    std::string salt;  // base64
    int iterations = 0;
    std::string blob;  // AEAD blob of the vault key
    std::string host;  // id of the host holding the secret (PROTOCOL.md §11); "" = the device's only host
};
std::optional<PinFile> loadPinFile(const std::string& path);  // nullopt if missing or unreadable
// Is this PIN the host's (PROTOCOL.md §11), so forgetting or re-pairing it must delete the PIN? A file without
// `host` is from before there were several hosts: it belongs to the PIN host, `pinHostId`, alone.
bool pinBelongsTo(const PinFile& f, const std::string& hostId, const std::string& pinHostId);
// The host a PIN unlocks with: the one pin.json names, if it's still among the dedicated hosts (their ids, best
// first); for a file without `host`, the best dedicated host. "" = none, so no PIN to offer.
std::string pinHostId(const PinFile& f, const std::vector<std::string>& dedicated);
void savePinFile(const std::string& path, const PinFile& f);  // mode 600; throws on failure
std::string readFile(const std::string& path);  // "" if missing
// Writes path + ".tmp", mode 600 before any content lands; the caller renames it into place. Throws on failure.
void writePrivateTmp(const std::string& path, const std::string& content);

std::string pinProofHex(const std::string& pin, const std::string& saltRaw, int iterations);  // slow, on purpose
std::string pinWrapKey(const std::string& secretHex, const std::string& proofHex);            // 32 bytes

#endif  // PIN_UNLOCK_H
