#ifndef ISALTED_ENCRYPTION_H
#define ISALTED_ENCRYPTION_H

#include <string>
#include <vector>

#include "encryption_interface.h"

// Abstract interface for encryption algorithms that use a salt
class ISaltedEncryption : public IEncryption {
   public:
    virtual ~ISaltedEncryption() = default;

    /**
     * @brief Encrypts multiple fields with the same salt.
     *
     * The implementation should generate a random salt (typically 16 bytes)
     * and prepend it to each of the resulting ciphertexts.
     *
     * @param plaintexts A vector of strings to encrypt.
     * @return A vector of strings, where each string is the salt prepended to the ciphertext.
     */
    virtual std::vector<std::string> encryptWithSalt(const std::vector<std::string>& plaintexts) = 0;

    /**
     * @brief Decrypts multiple fields that were encrypted with the same salt.
     *
     * The implementation should extract the salt from the first 16 bytes of the ciphertext.
     *
     * @param ciphertexts A vector of salted ciphertexts to decrypt.
     * @return A vector of decrypted plaintexts.
     */
    virtual std::vector<std::string> decryptWithSalt(const std::vector<std::string>& ciphertexts) = 0;
};

#endif  // ISALTED_ENCRYPTION_H
