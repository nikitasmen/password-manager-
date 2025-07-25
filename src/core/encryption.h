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
 * 3. RSA for asymmetric encryption
 */
class Encryption {
public:
    virtual ~Encryption() = default;
    
    // Core encryption operations - these should validate password
    virtual std::string encrypt(const std::string& plaintext) = 0;
    virtual std::string decrypt(const std::string& encrypted_text) = 0;
    virtual std::string encryptWithSalt(const std::string& plaintext) = 0;
    virtual std::string decryptWithSalt(const std::string& encrypted_text) = 0;
    
    // Configuration operations - these can be called during initialization
    virtual EncryptionType getAlgorithm() const = 0;
    virtual void setAlgorithm(EncryptionType newAlgorithm) = 0;
    virtual void setMasterPassword(const std::string& password) = 0;
    virtual std::string hash(const std::string& input) = 0;

    // Static methods for master password encryption/decryption
    static std::string decryptMasterPassword(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& initState, const std::string& encrypted, const std::string& masterPassword);
    static std::string encryptMasterPassword(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& initState, const std::string& masterPassword);
};

/**
 * @class EncryptionManager
 * @brief Concrete implementation that routes encryption operations to appropriate algorithms
 * 
 * This class acts as a facade that internally manages different encryption implementations
 * and routes operations based on the selected encryption type.
 */
class EncryptionManager : public Encryption {
private:
    EncryptionType currentAlgorithm;
    std::string masterPassword;
    std::vector<int> lfsrTaps;
    std::vector<int> lfsrInitState;
    std::string rsaPublicKey;
    std::string rsaPrivateKey;
    
    // Internal encryption instances
    std::unique_ptr<Encryption> aesEncryptor;
    std::unique_ptr<Encryption> lfsrEncryptor;
    std::unique_ptr<Encryption> rsaEncryptor;
    
    // Helper method to get the current encryptor
    Encryption* getCurrentEncryptor();
    void initializeEncryptors();
    
public:
    explicit EncryptionManager(EncryptionType algorithm = EncryptionType::AES);
    ~EncryptionManager() override = default;
    
    // Core encryption operations
    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& encrypted_text) override;
    std::string encryptWithSalt(const std::string& plaintext) override;
    std::string decryptWithSalt(const std::string& encrypted_text) override;
    
    // Configuration operations
    EncryptionType getAlgorithm() const override { return currentAlgorithm; }
    void setAlgorithm(EncryptionType newAlgorithm) override;
    void setMasterPassword(const std::string& password) override;
    std::string hash(const std::string& input) override;
    
    // RSA-specific methods
    void setRsaKeys(const std::string& publicKey, const std::string& privateKey = "");
    std::pair<std::string, std::string> generateRsaKeys();
};

namespace EncryptionFactory {
    std::unique_ptr<Encryption> create(EncryptionType type, const std::vector<int>& taps = {}, const std::vector<int>& init_state = {}, const std::string& password = "", const std::string& pubKey = "", const std::string& privKey = "");
}

#endif // ENCRYPTION_H
