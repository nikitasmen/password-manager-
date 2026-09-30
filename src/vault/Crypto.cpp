#include "Crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "../core/base64.h"
#include "../crypto/cipher_context_raii.h"

namespace {

constexpr size_t kKeyLen = 32, kNonceLen = 12, kTagLen = 16;

const unsigned char* u8(const std::string& s) {
    return reinterpret_cast<const unsigned char*>(s.data());
}
unsigned char* u8(std::string& s) {
    return reinterpret_cast<unsigned char*>(s.data());
}

void check(int ok, const char* what) {
    if (ok != 1) throw std::runtime_error(std::string("OpenSSL: ") + what + " failed");
}

// Both supported algorithms are OpenSSL EVP AEADs and share the exact same call sequence.
class OpenSslAead final : public ICipher {
   public:
    OpenSslAead(CipherAlg alg, const EVP_CIPHER* evp) : alg_(alg), evp_(evp) {
    }

    [[nodiscard]] CipherAlg alg() const override {
        return alg_;
    }

    [[nodiscard]] std::string seal(const std::string& key,
                                   const std::string& plaintext,
                                   const std::string& aad,
                                   const std::string& nonce) const override {
        if (key.size() != kKeyLen) throw std::invalid_argument("key must be 32 bytes");
        std::string n = nonce.empty() ? vaultcrypto::randomBytes(kNonceLen) : nonce;
        if (n.size() != kNonceLen) throw std::invalid_argument("nonce must be 12 bytes");

        CipherContextRAII ctx;
        std::string out(plaintext.size(), '\0'), tag(kTagLen, '\0');
        int len = 0;
        check(EVP_EncryptInit_ex(ctx, evp_, nullptr, nullptr, nullptr), "init");
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, kNonceLen, nullptr), "set iv len");
        check(EVP_EncryptInit_ex(ctx, nullptr, nullptr, u8(key), u8(n)), "set key");
        check(EVP_EncryptUpdate(ctx, nullptr, &len, u8(aad), static_cast<int>(aad.size())), "aad");
        check(EVP_EncryptUpdate(ctx, u8(out), &len, u8(plaintext), static_cast<int>(plaintext.size())), "encrypt");
        check(EVP_EncryptFinal_ex(ctx, u8(out) + len, &len), "final");
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, kTagLen, u8(tag)), "get tag");
        return base64::encode(n + out + tag);
    }

    [[nodiscard]] std::string open(const std::string& key,
                                   const std::string& blob,
                                   const std::string& aad) const override {
        if (key.size() != kKeyLen) throw std::invalid_argument("key must be 32 bytes");
        std::string raw = base64::decode(blob);
        if (raw.size() < kNonceLen + kTagLen) throw DecryptError();
        std::string nonce = raw.substr(0, kNonceLen);
        std::string ct = raw.substr(kNonceLen, raw.size() - kNonceLen - kTagLen);
        std::string tag = raw.substr(raw.size() - kTagLen);

        CipherContextRAII ctx;
        std::string out(ct.size(), '\0');
        int len = 0;
        check(EVP_DecryptInit_ex(ctx, evp_, nullptr, nullptr, nullptr), "init");
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, kNonceLen, nullptr), "set iv len");
        check(EVP_DecryptInit_ex(ctx, nullptr, nullptr, u8(key), u8(nonce)), "set key");
        check(EVP_DecryptUpdate(ctx, nullptr, &len, u8(aad), static_cast<int>(aad.size())), "aad");
        check(EVP_DecryptUpdate(ctx, u8(out), &len, u8(ct), static_cast<int>(ct.size())), "decrypt");
        check(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, kTagLen, u8(tag)), "set tag");
        if (EVP_DecryptFinal_ex(ctx, u8(out) + len, &len) != 1) {
            vaultcrypto::wipe(out);
            throw DecryptError();
        }
        return out;
    }

   private:
    CipherAlg alg_;
    const EVP_CIPHER* evp_;
};

}  // namespace

const char* cipherName(CipherAlg alg) {
    switch (alg) {
        case CipherAlg::Aes256Gcm:
            return "aes-256-gcm";
        case CipherAlg::ChaCha20Poly1305:
            return "chacha20-poly1305";
    }
    return "?";
}

std::optional<CipherAlg> cipherFromName(const std::string& name) {
    for (CipherAlg a : allCiphers())
        if (name == cipherName(a)) return a;
    return std::nullopt;
}

const std::vector<CipherAlg>& allCiphers() {
    static const std::vector<CipherAlg> all = {CipherAlg::Aes256Gcm, CipherAlg::ChaCha20Poly1305};
    return all;
}

std::unique_ptr<ICipher> makeCipher(CipherAlg alg) {
    switch (alg) {
        case CipherAlg::Aes256Gcm:
            return std::make_unique<OpenSslAead>(alg, EVP_aes_256_gcm());
        case CipherAlg::ChaCha20Poly1305:
            return std::make_unique<OpenSslAead>(alg, EVP_chacha20_poly1305());
    }
    throw std::invalid_argument("unknown cipher");
}

namespace vaultcrypto {

std::string randomBytes(size_t n) {
    std::string out(n, '\0');
    check(RAND_bytes(u8(out), static_cast<int>(n)), "RAND_bytes");
    return out;
}

std::string pbkdf2Sha256(const std::string& password, const std::string& salt, int iterations) {
    std::string key(kKeyLen, '\0');
    check(PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), u8(salt), static_cast<int>(salt.size()),
                            iterations, EVP_sha256(), static_cast<int>(kKeyLen), u8(key)),
          "PBKDF2");
    return key;
}

std::string hmacSha256(const std::string& key, const std::string& message) {
    std::string mac(32, '\0');
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), u8(message), message.size(), u8(mac), &len))
        throw std::runtime_error("OpenSSL: HMAC failed");
    return mac;
}

std::string sha256Hex(const std::string& data) {
    unsigned char h[32];
    unsigned int n = 0;
    if (!EVP_Digest(data.data(), data.size(), h, &n, EVP_sha256(), nullptr)) throw std::runtime_error("OpenSSL: SHA-256 failed");
    return toHex(std::string(reinterpret_cast<char*>(h), n));
}

std::string toHex(const std::string& bytes) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char c : bytes) {
        out += digits[c >> 4];
        out += digits[c & 15];
    }
    return out;
}

void wipe(std::string& secret) {
    OPENSSL_cleanse(secret.data(), secret.size());
    secret.clear();
}

}  // namespace vaultcrypto
