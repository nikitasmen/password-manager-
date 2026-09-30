#ifndef PIN_UNLOCK_H
#define PIN_UNLOCK_H

#include <optional>
#include <string>

// PIN unlock, this device's half (the board's half and the scheme: header comment of esp32/vault/vault.ino).
// This device keeps the vault key wrapped with HMAC(board secret, proof), proof = PBKDF2(PIN, salt). The board
// releases the secret only for the right proof and deletes it after 5 wrong ones, so a PIN can't be guessed
// offline from this file. The master password stays the real key.

bool validPin(const std::string& pin);  // at least 4 digits, digits only

struct PinFile {
    std::string vaultId;  // the vault this PIN opens
    std::string salt;     // base64
    int iterations = 0;
    std::string blob;  // AEAD blob of the vault key
};
std::optional<PinFile> loadPinFile(const std::string& path);  // nullopt if missing or unreadable
void savePinFile(const std::string& path, const PinFile& f);  // mode 600; throws on failure

std::string pinProofHex(const std::string& pin, const std::string& saltRaw, int iterations);  // slow, on purpose
std::string pinVerifierHex(const std::string& proofHex);                                      // what the board stores
std::string pinWrapKey(const std::string& secretHex, const std::string& proofHex);            // 32 bytes

#endif  // PIN_UNLOCK_H
