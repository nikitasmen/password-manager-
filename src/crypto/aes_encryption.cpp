#include "aes_encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <memory>

std::string AesEncryption::encrypt(const std::string& plaintext) {
    if (masterPassword.empty()) {
        throw EncryptionError("Cannot encrypt: master password not set");
    }
    return aesEncrypt(plaintext, masterPassword);
}

std::string AesEncryption::decrypt(const std::string& encrypted_text) {
    if (masterPassword.empty()) {
        throw EncryptionError("Cannot decrypt: master password not set");
    }
    return aesDecrypt(encrypted_text, masterPassword);
}

std::string AesEncryption::encryptWithSalt(const std::string& plaintext) {
    if (masterPassword.empty()) {
        throw EncryptionError("Cannot encrypt: master password not set");
    }
    return encrypt(plaintext);
}

std::string AesEncryption::decryptWithSalt(const std::string& encrypted_text) {
    if (masterPassword.empty()) {
        throw EncryptionError("Cannot decrypt: master password not set");
    }
    return decrypt(encrypted_text);
}

void AesEncryption::setMasterPassword(const std::string& password) {
    if (password.empty()) {
        throw EncryptionError("Master password cannot be empty");
    }
    masterPassword = password;
}

std::string AesEncryption::hash(const std::string& input) {
    return computeSha256(input);
}

std::string AesEncryption::aesEncrypt(const std::string& plaintext, const std::string& key) {
    if (key.empty()) {
        throw EncryptionError("Encryption key cannot be empty");
    }

    // Handle empty input case
    if (plaintext.empty()) {
        auto salt = generateSalt();
        std::string result;
        result.reserve(PBKDF2_SALT_SIZE + AES_IV_SIZE);
        result.append(reinterpret_cast<char*>(salt.data()), PBKDF2_SALT_SIZE);
        unsigned char iv[AES_IV_SIZE] = {0};
        result.append(reinterpret_cast<char*>(iv), AES_IV_SIZE);
        return result;
    }

    auto salt = generateSalt();
    auto deriveKeyResult = deriveKey(key, salt);
    
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw EncryptionError("Failed to create encryption context");
    }

    unsigned char iv[AES_IV_SIZE];
    if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
        throw EncryptionError("Failed to generate IV");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, deriveKeyResult.data(), iv) != 1) {
        throw EncryptionError("Failed to initialize encryption");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        static_cast<int>(plaintext.size())) != 1) {
        throw EncryptionError("Failed to encrypt data");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
        throw EncryptionError("Failed to finalize encryption");
    }
    ciphertext_len += len;

    std::string result;
    result.reserve(PBKDF2_SALT_SIZE + AES_IV_SIZE + ciphertext_len);
    result.append(reinterpret_cast<char*>(salt.data()), PBKDF2_SALT_SIZE);
    result.append(reinterpret_cast<char*>(iv), AES_IV_SIZE);
    result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    return result;
}

std::string AesEncryption::aesDecrypt(const std::string& ciphertext, const std::string& key) {
    if (key.empty()) {
        throw EncryptionError("Decryption key cannot be empty");
    }

    if (ciphertext.size() < PBKDF2_SALT_SIZE + AES_IV_SIZE) {
        throw EncryptionError("Invalid ciphertext size");
    }

    // Handle special case for empty encrypted data
    if (ciphertext.size() == PBKDF2_SALT_SIZE + AES_IV_SIZE) {
        return "";
    }

    std::array<unsigned char, PBKDF2_SALT_SIZE> salt;
    std::copy(ciphertext.begin(), ciphertext.begin() + PBKDF2_SALT_SIZE, salt.begin());
    auto deriveKeyResult = deriveKey(key, salt);

    const unsigned char* iv = reinterpret_cast<const unsigned char*>(ciphertext.data() + PBKDF2_SALT_SIZE);
    const unsigned char* encrypted_data = iv + AES_IV_SIZE;
    int encrypted_len = static_cast<int>(ciphertext.size() - PBKDF2_SALT_SIZE - AES_IV_SIZE);

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw EncryptionError("Failed to create decryption context");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, deriveKeyResult.data(), iv) != 1) {
        throw EncryptionError("Failed to initialize decryption");
    }

    std::vector<unsigned char> plaintext(encrypted_len + AES_BLOCK_SIZE);
    int len = 0, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, encrypted_data, encrypted_len) != 1) {
        throw EncryptionError("Failed to decrypt data");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1) {
        throw EncryptionError("Failed to finalize decryption");
    }
    plaintext_len += len;

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

std::array<unsigned char, AES_KEY_SIZE> AesEncryption::deriveKey(const std::string& password, const std::array<unsigned char, PBKDF2_SALT_SIZE>& salt) {
    if (password.empty()) {
        throw EncryptionError("Cannot derive key from empty password");
    }

    std::array<unsigned char, AES_KEY_SIZE> key;
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), PBKDF2_SALT_SIZE,
                          PBKDF2_ITERATIONS, EVP_sha256(),
                          AES_KEY_SIZE, key.data()) != 1) {
        throw EncryptionError("Key derivation failed");
    }
    return key;
}

std::array<unsigned char, PBKDF2_SALT_SIZE> AesEncryption::generateSalt() {
    std::array<unsigned char, PBKDF2_SALT_SIZE> salt;
    if (RAND_bytes(salt.data(), PBKDF2_SALT_SIZE) != 1) {
        throw EncryptionError("Failed to generate salt");
    }
    return salt;
}

std::string AesEncryption::computeSha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()),
           input.size(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
    }
    return ss.str();
} 