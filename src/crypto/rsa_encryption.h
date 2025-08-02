#ifndef RSA_ENCRYPTION_H
#define RSA_ENCRYPTION_H

#include "encryption_interface.h"
#include <string>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/**
 * @brief RSA implementation of the IEncryption interface
 * 
 * This class provides RSA encryption and decryption functionality.
 * It generates an RSA key pair on initialization and uses it for all operations.
 * The public key is used for encryption and the private key for decryption.
 */
class RSAEncryption : public IEncryption {
public:
    /**
     * @brief Construct a new RSAEncryption object
     * 
     * @param keySize The size of the RSA key in bits (default: 2048)
     * @param publicKey Optional public key in PEM format. If not provided, a new key pair will be generated.
     * @param privateKey Optional private key in PEM format. Must be provided if publicKey is provided.
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
     * @brief Get the public key in PEM format
     * 
     * @return std::string The public key in PEM format
     */
    std::string getPublicKey() const;
    
    /**
     * @brief Get the private key in PEM format
     * 
     * @return std::string The private key in PEM format
     */
    std::string getPrivateKey() const;
    
    void loadKeys(const std::string& publicKey, const std::string& privateKey);
    void generateKeyPair(int keySize);
    
private:
    [[noreturn]] void throwOpenSSLError(const std::string& message) const;

    EVP_PKEY* m_pkey;
    std::string m_masterPassword;
    int m_keySize;
};

#endif // RSA_ENCRYPTION_H
