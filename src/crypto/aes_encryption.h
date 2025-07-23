#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include "../core/encryption.h"
#include <string>

class AesEncryption : public Encryption {
private:
    std::string masterPassword;
    std::string aesEncrypt(const std::string& plaintext, const std::string& key);
    std::string aesDecrypt(const std::string& ciphertext, const std::string& key);
    std::array<unsigned char, AES_KEY_SIZE> deriveKey(const std::string& password, const std::array<unsigned char, PBKDF2_SALT_SIZE>& salt);
    std::array<unsigned char, PBKDF2_SALT_SIZE> generateSalt();
    std::string computeSha256(const std::string& input); // Helper

public:
    AesEncryption(const std::string& password);
    
    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& encrypted_text) override;
    std::string encryptWithSalt(const std::string& plaintext) override;
    std::string decryptWithSalt(const std::string& encrypted_text) override;
    EncryptionType getAlgorithm() const override { return EncryptionType::AES; }
    void setAlgorithm(EncryptionType newAlgorithm) override {} // Not supported
    void setMasterPassword(const std::string& password) override;
    std::string hash(const std::string& input) override;
};

#endif 