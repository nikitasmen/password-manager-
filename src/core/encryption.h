#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <array>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include "../crypto/encryption_interface.h"
#include "../crypto/encryption_factory.h"
#include "../config/GlobalConfig.h"

// Constants for encryption
constexpr size_t AES_BLOCK_SIZE = 16;    // AES uses 128-bit (16-byte) blocks
constexpr size_t AES_KEY_SIZE = 32;      // 256 bits
constexpr size_t AES_IV_SIZE = 16;       // 128 bits
constexpr size_t PBKDF2_ITERATIONS = 10000;
constexpr size_t PBKDF2_SALT_SIZE = 16;

/**
 * @brief RAII wrapper for OpenSSL's EVP_CIPHER_CTX
 */
class CipherContextRAII {
    EVP_CIPHER_CTX* ctx_;

public:
    CipherContextRAII();
    ~CipherContextRAII();
    CipherContextRAII(CipherContextRAII&& other) noexcept;
    CipherContextRAII& operator=(CipherContextRAII&& other) noexcept;
    
    // Disable copy
    CipherContextRAII(const CipherContextRAII&) = delete;
    CipherContextRAII& operator=(const CipherContextRAII&) = delete;
    
    operator EVP_CIPHER_CTX*() { return ctx_; }
    EVP_CIPHER_CTX* get() { return ctx_; }
};

/**
 * @brief Implementation of IEncryption that provides encryption/decryption
 *        using different algorithms through the factory pattern
 */
class Encryption : public IEncryption {
private:
    std::vector<int> taps_;
    std::vector<int> initialState_;
    std::string masterPassword_;
    EncryptionType algorithm_;

    // Helper methods
    std::string lfsrProcess(const std::string& input);
    std::string aesEncrypt(const std::string& plaintext, const std::string& key);
    std::string aesDecrypt(const std::string& ciphertext, const std::string& key);
    std::array<unsigned char, PBKDF2_SALT_SIZE> generateSalt();
    std::array<unsigned char, AES_KEY_SIZE> deriveKey(
        const std::string& password, 
        const std::array<unsigned char, PBKDF2_SALT_SIZE>& salt);

public:
    // Salt-based encryption/decryption methods
    std::string encryptWithSalt(const std::string& plaintext);
    std::string decryptWithSalt(const std::string& ciphertext);

    /**
     * @brief Get the current encryption algorithm
     */
    EncryptionType getAlgorithm() const { return algorithm_; }
    
    /**
     * @brief Set the encryption algorithm
     */
    void setAlgorithm(EncryptionType newAlgorithm) { algorithm_ = newAlgorithm; }

    // IEncryption interface implementation
    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& ciphertext) override;
    EncryptionType getType() const override { return algorithm_; }
    void setMasterPassword(const std::string& password) override;

    /**
     * @brief Construct a new Encryption object
     * 
     * @param algorithm The encryption algorithm to use
     * @param taps Taps for LFSR (only used if algorithm is LFSR)
     * @param initState Initial state for LFSR (only used if algorithm is LFSR)
     * @param password The master password to use for encryption/decryption
     */
    Encryption(EncryptionType algorithm = EncryptionType::AES, 
              const std::vector<int>& taps = {0, 2}, 
              const std::vector<int>& initState = {1, 0, 1, 1, 0, 1, 0, 1},
              const std::string& password = "");

    /**
     * @brief Static method to decrypt a master password
     */
    static std::string decryptMasterPassword(EncryptionType type, 
                                          const std::vector<int>& taps, 
                                          const std::vector<int>& initState, 
                                          const std::string& encrypted, 
                                          const std::string& masterPassword);

    /**
     * @brief Static method to encrypt a master password
     */
    static std::string encryptMasterPassword(EncryptionType type, 
                                          const std::vector<int>& taps, 
                                          const std::vector<int>& initState, 
                                          const std::string& masterPassword);

private:
};

#endif // ENCRYPTION_H
