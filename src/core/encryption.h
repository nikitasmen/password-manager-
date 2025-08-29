#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <memory>
#include <string>
#include <vector>

#include "../config/GlobalConfig.h"
#include "../crypto/encryption_factory.h"
#include "../crypto/encryption_interface.h"

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
    std::unique_ptr<IEncryption> encryptor_;  // Cached encryptor instance
    bool needsRecreation_ = false;            // Flag to track when encryptor needs recreation

    // Updates the encryptor instance based on current settings
    void updateEncryptor();

   public:
    /**
     * @brief Get the current encryption algorithm
     */
    EncryptionType getAlgorithm() const {
        return algorithm_;
    }

    /**
     * @brief Set the encryption algorithm
     * @param newAlgorithm The new encryption algorithm to use
     */
    void setAlgorithm(EncryptionType newAlgorithm);

    // IEncryption interface implementation
    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& ciphertext) override;
    EncryptionType getType() const override {
        return algorithm_;
    }
    void setMasterPassword(const std::string& password) override;

    /**
     * @brief Encrypt multiple strings with salt
     * @param plaintexts Vector of strings to encrypt
     * @return Vector of encrypted strings
     */
    std::vector<std::string> encryptWithSalt(const std::vector<std::string>& plaintexts);

    /**
     * @brief Decrypt multiple strings with salt
     * @param ciphertexts Vector of encrypted strings
     * @return Vector of decrypted strings
     */
    std::vector<std::string> decryptWithSalt(const std::vector<std::string>& ciphertexts);

    /**
     * @brief Encrypt a single string with salt
     * @param plaintext String to encrypt
     * @return Encrypted string
     */
    std::string encryptWithSalt(const std::string& plaintext);

    /**
     * @brief Decrypt a single string with salt
     * @param ciphertext String to decrypt
     * @return Decrypted string
     */
    std::string decryptWithSalt(const std::string& ciphertext);

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

#endif  // ENCRYPTION_H
