#ifndef RSA_ENCRYPTION_H
#define RSA_ENCRYPTION_H

#include "encryption_interface.h"
#include <string>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

/**
 * @brief RSA Hybrid Encryption implementation
 * 
 * This class implements secure hybrid encryption using RSA + AES:
 * 1. Generates a random AES-256 key for each encryption operation
 * 2. Uses RSA to encrypt the AES key
 * 3. Uses AES-256-GCM to encrypt the actual data
 * 4. Stores: RSA-encrypted AES key + AES-encrypted data + authentication tag
 * 
 * This approach is secure, performant, and follows industry standards.
 * The master password is used to derive and protect the RSA private key.
 */
class RSAEncryption : public IEncryption {
public:
    /**
     * @brief Construct a new RSAEncryption object
     * 
     * @param keySize The size of the RSA key in bits (default: 2048)
     */
    explicit RSAEncryption(int keySize = 2048);
    
    ~RSAEncryption() override;
    
    // Delete copy constructor and assignment operator
    RSAEncryption(const RSAEncryption&) = delete;
    RSAEncryption& operator=(const RSAEncryption&) = delete;
    
    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& ciphertext) override;
    
    EncryptionType getType() const override { return EncryptionType::RSA; }
    void setMasterPassword(const std::string& password) override;
    
    /**
     * @brief Get the public key in PEM format (safe to store)
     * 
     * @return std::string The public key in PEM format
     */
    std::string getPublicKey() const;
    
    /**
     * @brief Get encrypted private key data for storage
     * Only returns key encrypted with master password
     * 
     * @return std::string The encrypted private key data
     */
    std::string getEncryptedPrivateKeyData() const;
    
    /**
     * @brief Load keys from stored data
     * 
     * @param publicKey The public key in PEM format
     * @param encryptedPrivateData The encrypted private key data
     */
    void loadKeys(const std::string& publicKey, const std::string& encryptedPrivateData);
    
    /**
     * @brief Generate a new RSA key pair
     * 
     * @param keySize The key size in bits
     */
    void generateKeyPair(int keySize);
    
    /**
     * @brief Check if keys are properly initialized
     */
    bool isInitialized() const;
    
private:
    struct HybridData {
        std::string encryptedAESKey;  // RSA-encrypted AES key
        std::string iv;               // AES initialization vector
        std::string encryptedData;    // AES-encrypted actual data
        std::string authTag;          // GCM authentication tag
    };
    
    /**
     * @brief Serialize hybrid data to string
     */
    std::string serializeHybridData(const HybridData& data) const;
    
    /**
     * @brief Deserialize hybrid data from string
     */
    HybridData deserializeHybridData(const std::string& serialized) const;
    
    /**
     * @brief Generate random AES key
     */
    std::string generateAESKey() const;
    
    /**
     * @brief Encrypt data using AES-256-GCM
     */
    HybridData encryptWithAES(const std::string& plaintext, const std::string& aesKey) const;
    
    /**
     * @brief Decrypt data using AES-256-GCM
     */
    std::string decryptWithAES(const HybridData& data, const std::string& aesKey) const;
    
    /**
     * @brief Encrypt AES key using RSA
     */
    std::string encryptAESKeyWithRSA(const std::string& aesKey) const;
    
    /**
     * @brief Decrypt AES key using RSA
     */
    std::string decryptAESKeyWithRSA(const std::string& encryptedAESKey) const;
    
    /**
     * @brief Derive key encryption key from master password
     */
    std::string deriveKEK(const std::string& masterPassword, const std::string& salt) const;
    
    /**
     * @brief Encrypt private key with master password
     */
    std::string encryptPrivateKey() const;
    
    /**
     * @brief Decrypt private key with master password
     */
    void decryptPrivateKey(const std::string& encryptedData);
    
    [[noreturn]] void throwOpenSSLError(const std::string& message) const;
    
    EVP_PKEY* m_pkey;
    std::string m_masterPassword;
    std::string m_keySalt;  // Salt for key derivation
    int m_keySize;
    bool m_initialized;
};

#endif // RSA_HYBRID_ENCRYPTION_H