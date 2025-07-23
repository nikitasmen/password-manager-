#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <stdexcept>
#include <mutex>
#include <array>
#include <optional>
#include <memory>
#include "../config/GlobalConfig.h"

// Forward declaration for OpenSSL context
struct evp_cipher_ctx_st;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

// Exception class for encryption errors
class EncryptionError : public std::runtime_error {
public:
    explicit EncryptionError(const std::string& message) 
        : std::runtime_error("Encryption Error: " + message) {}
};

// RAII wrapper for OpenSSL EVP_CIPHER_CTX to ensure proper resource management
class CipherContextRAII {
public:
    CipherContextRAII();
    ~CipherContextRAII();
    
    // Delete copy constructor and assignment operator to prevent resource issues
    CipherContextRAII(const CipherContextRAII&) = delete;
    CipherContextRAII& operator=(const CipherContextRAII&) = delete;
    
    // Allow move semantics
    CipherContextRAII(CipherContextRAII&& other) noexcept;
    CipherContextRAII& operator=(CipherContextRAII&& other) noexcept;
    
    // Get the raw context pointer for OpenSSL operations
    EVP_CIPHER_CTX* get() const noexcept { return ctx_; }
    
    // Check if context is valid
    bool is_valid() const noexcept { return ctx_ != nullptr; }

private:
    EVP_CIPHER_CTX* ctx_;
};

// Constants for AES implementation
constexpr size_t AES_BLOCK_SIZE = 16;  // AES uses 128-bit (16-byte) blocks
constexpr size_t AES_KEY_SIZE = 32;    // Using AES-256 (32-byte key)
constexpr size_t AES_IV_SIZE = 16;     // Initialization vector size

// Constants for PBKDF2 key derivation
constexpr size_t PBKDF2_SALT_SIZE = 16;    // 128-bit salt (sufficient for security)
constexpr int PBKDF2_ITERATIONS = 100000;  // Number of PBKDF2 iterations (NIST recommended minimum)

/**
 * @class Encryption
 * @brief Provides encryption and decryption functionality with multiple algorithms
 * 
 * This class implements multiple encryption mechanisms:
 * 1. LFSR-based stream cipher (original implementation)
 * 2. AES-256 for stronger encryption
 */
class Encryption {
public:
    virtual ~Encryption() = default;

    virtual std::string encrypt(const std::string& plaintext) = 0;
    virtual std::string decrypt(const std::string& encrypted_text) = 0;
    virtual std::string encryptWithSalt(const std::string& plaintext) = 0;
    virtual std::string decryptWithSalt(const std::string& encrypted_text) = 0;
    virtual EncryptionType getAlgorithm() const = 0;
    virtual void setAlgorithm(EncryptionType newAlgorithm) = 0;
    virtual void setMasterPassword(const std::string& password) = 0;
    // Add virtual hash for hashing support
    virtual std::string hash(const std::string& input) = 0;

    // Keep static methods if needed
    static std::string decryptMasterPassword(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& initState, const std::string& encrypted, const std::string& masterPassword);
    static std::string encryptMasterPassword(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& initState, const std::string& masterPassword);
};

namespace EncryptionFactory {
    std::unique_ptr<Encryption> create(EncryptionType type, const std::vector<int>& taps = {}, const std::vector<int>& init_state = {}, const std::string& password = "");
}

#endif // ENCRYPTION_H
