#ifndef ENCRYPTION_INTERFACE_H
#define ENCRYPTION_INTERFACE_H

#include <string>
#include <vector>

#include "../config/GlobalConfig.h"

// Exception class for encryption errors
class EncryptionError : public std::runtime_error {
   public:
    explicit EncryptionError(const std::string& message) : std::runtime_error("Encryption Error: " + message) {
    }
};

/**
 * @brief Interface for encryption algorithms
 */
class IEncryption {
   public:
    virtual ~IEncryption() = default;

    // Disable copy and move to prevent object slicing
    IEncryption(const IEncryption&) = delete;
    IEncryption& operator=(const IEncryption&) = delete;
    IEncryption(IEncryption&&) = delete;
    IEncryption& operator=(IEncryption&&) = delete;

    /**
     * @brief Encrypts the given plaintext
     * @param plaintext The text to encrypt
     * @return std::string The encrypted text
     */
    virtual std::string encrypt(const std::string& plaintext) = 0;

    /**
     * @brief Decrypts the given ciphertext
     * @param ciphertext The text to decrypt
     * @return std::string The decrypted text
     */
    virtual std::string decrypt(const std::string& ciphertext) = 0;

    /**
     * @brief Gets the encryption type
     * @return EncryptionType The type of encryption
     */
    [[nodiscard]] virtual EncryptionType getType() const = 0;

    /**
     * @brief Sets the master password for the encryption
     * @param password The master password
     */
    virtual void setMasterPassword(const std::string& password) = 0;

   protected:
    // Allow derived classes to construct
    IEncryption() = default;
};

// Extended interface for salted encryption/decryption
class ISaltedEncryption : public IEncryption {
   public:
    ~ISaltedEncryption() override = default;

    // Disable copy and move to prevent object slicing
    ISaltedEncryption(const ISaltedEncryption&) = delete;
    ISaltedEncryption& operator=(const ISaltedEncryption&) = delete;
    ISaltedEncryption(ISaltedEncryption&&) = delete;
    ISaltedEncryption& operator=(ISaltedEncryption&&) = delete;

    // Batch encryption/decryption with salt
    virtual std::vector<std::string> encryptWithSalt(const std::vector<std::string>& plaintexts) = 0;
    virtual std::vector<std::string> decryptWithSalt(const std::vector<std::string>& ciphertexts) = 0;

   protected:
    // Allow derived classes to construct
    ISaltedEncryption() = default;
};

#endif  // ENCRYPTION_INTERFACE_H
