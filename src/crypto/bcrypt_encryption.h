#ifndef BCRYPT_ENCRYPTION_H
#define BCRYPT_ENCRYPTION_H

#include "../core/encryption.h"
#include <string>

class BcryptEncryption : public Encryption {
private:
    std::string computeSha256(const std::string& input); // Placeholder for bcrypt

public:
    BcryptEncryption();
    
    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& encrypted_text) override;
    std::string encryptWithSalt(const std::string& plaintext) override;
    std::string decryptWithSalt(const std::string& encrypted_text) override;
    EncryptionType getAlgorithm() const override { return EncryptionType::BCRYPT; }
    void setAlgorithm(EncryptionType newAlgorithm) override {} // Not supported
    void setMasterPassword(const std::string& password) override {} // Not used
    std::string hash(const std::string& input) override;
};

#endif 