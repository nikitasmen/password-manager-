#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include "encryption_interface.h"
#include <array>
#include <vector>
#include <mutex>

// Forward declaration for OpenSSL context
struct evp_cipher_ctx_st;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

// RAII wrapper for OpenSSL EVP_CIPHER_CTX
class CipherContextRAII {
public:
    CipherContextRAII();
    ~CipherContextRAII();
    
    // Delete copy constructor and assignment operator
    CipherContextRAII(const CipherContextRAII&) = delete;
    CipherContextRAII& operator=(const CipherContextRAII&) = delete;
    
    // Move semantics
    CipherContextRAII(CipherContextRAII&& other) noexcept;
    CipherContextRAII& operator=(CipherContextRAII&& other) noexcept;
    
    // Get the raw context pointer
    EVP_CIPHER_CTX* get() const noexcept { return ctx_; }
    
    // Check if context is valid
    bool isValid() const noexcept { return ctx_ != nullptr; }

private:
    EVP_CIPHER_CTX* ctx_;
};

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
