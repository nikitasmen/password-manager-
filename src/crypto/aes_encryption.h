#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include "encryption_interface.h"
#include "cipher_context_raii.h"
#include <array>
#include <vector>
#include <mutex>

// Forward declaration for OpenSSL context
struct evp_cipher_ctx_st;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

// CipherContextRAII is now defined in cipher_context_raii.h

/**
 * @brief AES-256 encryption implementation using OpenSSL
 */
class AESEncryption : public IEncryption {
public:
    static constexpr size_t KEY_SIZE = 32;      // 256 bits
    static constexpr size_t IV_SIZE = 16;       // 128 bits
    static constexpr size_t SALT_SIZE = 16;     // 128 bits
    static constexpr size_t ITERATIONS = 10000; // PBKDF2 iterations
    
    /**
     * @brief Construct a new AESEncryption object
     */
    AESEncryption();
    
    // IEncryption interface implementation
    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& ciphertext) override;
    EncryptionType getType() const override { return EncryptionType::AES; }
    void setMasterPassword(const std::string& password) override;
    
private:
    std::vector<unsigned char> generateSalt();
    std::vector<unsigned char> deriveKey(const std::vector<unsigned char>& salt);
    
    std::string masterPassword_;
    mutable std::mutex mutex_;
};

#endif // AES_ENCRYPTION_H
