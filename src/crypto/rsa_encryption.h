#ifndef RSA_ENCRYPTION_H
#define RSA_ENCRYPTION_H

#include "../config/GlobalConfig.h" // Must come before encryption.h for enum
#include "../core/encryption.h"
#include <string>
#include <utility>
#include <array>

class RsaEncryption : public Encryption {
private:
    std::string publicKey;
    std::string privateKey;
    bool hasPrivateKey;
public:
    // Default constructor (no keys)
    RsaEncryption() : publicKey(""), privateKey(""), hasPrivateKey(false) {}
    // Constructor with public and optional private key
    RsaEncryption(const std::string& pubKey, const std::string& privKey = "");

    // Encrypt/decrypt methods
    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& encrypted_text) override;
    std::string encryptWithSalt(const std::string& plaintext) override;
    std::string decryptWithSalt(const std::string& encrypted_text) override;
    EncryptionType getAlgorithm() const override { return EncryptionType::RSA; }
    void setAlgorithm(EncryptionType newAlgorithm) override {} // Not supported
    void setMasterPassword(const std::string& password) override {} // Not used for RSA
    std::string hash(const std::string& input) override;

    // Key management
    static std::pair<std::string, std::string> generateKeyPair(); // returns (public, private)
};

#endif 