#ifndef VAULT_CRYPTO_H
#define VAULT_CRYPTO_H

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// Byte strings are std::string throughout (matches base64:: and keeps key wiping simple).

enum class CipherAlg { Aes256Gcm, ChaCha20Poly1305 };

// Wire names from docs/PROTOCOL.md §2
const char* cipherName(CipherAlg alg);
std::optional<CipherAlg> cipherFromName(const std::string& name);
const std::vector<CipherAlg>& allCiphers();

// Thrown when an AEAD tag doesn't verify: wrong key or tampered data.
class DecryptError : public std::runtime_error {
   public:
    DecryptError() : std::runtime_error("decryption failed (wrong key or tampered data)") {
    }
};

/**
 * Authenticated encryption with associated data. A blob is base64(nonce(12) || ciphertext || tag(16)).
 * New algorithms are added by implementing this and registering them in makeCipher().
 */
class ICipher {
   public:
    virtual ~ICipher() = default;
    [[nodiscard]] virtual CipherAlg alg() const = 0;
    // `nonce` is for deterministic test vectors only; empty = fresh random nonce (always, in real use).
    [[nodiscard]] virtual std::string seal(const std::string& key,
                                           const std::string& plaintext,
                                           const std::string& aad,
                                           const std::string& nonce = "") const = 0;
    // Throws DecryptError if the tag doesn't verify.
    [[nodiscard]] virtual std::string open(const std::string& key,
                                           const std::string& blob,
                                           const std::string& aad) const = 0;
};

std::unique_ptr<ICipher> makeCipher(CipherAlg alg);

namespace vaultcrypto {
std::string randomBytes(size_t n);
std::string pbkdf2Sha256(const std::string& password, const std::string& salt, int iterations);
std::string hmacSha256(const std::string& key, const std::string& message);
std::string toHex(const std::string& bytes);
void wipe(std::string& secret);  // overwrite before release
}  // namespace vaultcrypto

#endif  // VAULT_CRYPTO_H
