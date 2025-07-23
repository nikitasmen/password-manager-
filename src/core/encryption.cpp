#include "./encryption.h"
#include <stdexcept>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include "../crypto/aes_encryption.h"
#include "../crypto/lfsr_encryption.h"
#include "../crypto/bcrypt_encryption.h"

// Static methods
std::string Encryption::decryptMasterPassword(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& initState, const std::string& encrypted, const std::string& masterPassword) {
    auto enc = EncryptionFactory::create(type, taps, initState, masterPassword);
    if (type == EncryptionType::LFSR) {
        return enc->decryptWithSalt(encrypted);
    } else if (type == EncryptionType::AES) {
        return enc->decrypt(encrypted);
    } else if (type == EncryptionType::BCRYPT) {
        if (enc->hash(masterPassword) == encrypted) {
            return masterPassword;
        } else {
            throw std::runtime_error("Invalid password");
        }
    }
    throw std::runtime_error("Unknown encryption type");
}

std::string Encryption::encryptMasterPassword(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& initState, const std::string& masterPassword) {
    auto enc = EncryptionFactory::create(type, taps, initState, masterPassword);
    if (type == EncryptionType::LFSR) {
        return enc->encryptWithSalt(masterPassword);
    } else if (type == EncryptionType::AES) {
        return enc->encrypt(masterPassword);
    } else if (type == EncryptionType::BCRYPT) {
        return enc->hash(masterPassword);
    }
    throw std::runtime_error("Unknown encryption type");
}

namespace EncryptionFactory {
    std::unique_ptr<Encryption> create(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& init_state, const std::string& password) {
        switch (type) {
            case EncryptionType::AES:
                return std::make_unique<AesEncryption>(password);
            case EncryptionType::LFSR:
                return std::make_unique<LfsrEncryption>(taps, init_state, password);
            case EncryptionType::BCRYPT:
                return std::make_unique<BcryptEncryption>();
            default:
                throw EncryptionError("Unknown encryption type");
        }
    }
}
