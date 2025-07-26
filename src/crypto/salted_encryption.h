#ifndef ISALTED_ENCRYPTION_H
#define ISALTED_ENCRYPTION_H

#include "encryption_interface.h"
#include <string>
#include <vector>

// Abstract interface for encryption algorithms that use a salt
class ISaltedEncryption : public IEncryption {
public:
    virtual ~ISaltedEncryption() = default;

    // Encrypts multiple fields with the same salt
    virtual std::vector<std::string> encryptWithSalt(const std::vector<std::string>& plaintexts) = 0;

    // Decrypts multiple fields with the same salt
    virtual std::vector<std::string> decryptWithSalt(const std::vector<std::string>& ciphertexts) = 0;
};

#endif // ISALTED_ENCRYPTION_H
