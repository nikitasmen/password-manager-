#include "bcrypt_encryption.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>

BcryptEncryption::BcryptEncryption() {}

std::string BcryptEncryption::computeSha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::string BcryptEncryption::encrypt(const std::string& plaintext) {
    return computeSha256(plaintext);
}

std::string BcryptEncryption::decrypt(const std::string& encrypted_text) {
    throw EncryptionError("Cannot decrypt hashed data");
}

std::string BcryptEncryption::encryptWithSalt(const std::string& plaintext) {
    unsigned char salt[16];
    RAND_bytes(salt, 16);
    std::string salted = plaintext + std::string(reinterpret_cast<char*>(salt), 16);
    return computeSha256(salted);
}

std::string BcryptEncryption::decryptWithSalt(const std::string& encrypted_text) {
    throw EncryptionError("Cannot decrypt hashed data");
}

std::string BcryptEncryption::hash(const std::string& input) {
    return computeSha256(input);
}
// Note: Replace with actual bcrypt from repo 