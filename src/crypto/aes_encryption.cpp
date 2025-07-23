#include "aes_encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>

// Implement aesEncrypt, aesDecrypt, deriveKey, generateSalt from original

AesEncryption::AesEncryption(const std::string& password) : masterPassword(password) {}

// Implement virtual methods using the private helpers

std::string AesEncryption::aesEncrypt(const std::string& plaintext, const std::string& key) {
    auto salt = generateSalt();
    auto deriveKeyResult = deriveKey(key, salt);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw EncryptionError("Failed to create context");
    unsigned char iv[AES_IV_SIZE];
    if (RAND_bytes(iv, AES_IV_SIZE) != 1) { EVP_CIPHER_CTX_free(ctx); throw EncryptionError("Failed to generate IV"); }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, deriveKeyResult.data(), iv) != 1) { EVP_CIPHER_CTX_free(ctx); throw EncryptionError("Init failed"); }
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len = 0, ciphertext_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) { EVP_CIPHER_CTX_free(ctx); throw EncryptionError("Update failed"); }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); throw EncryptionError("Final failed"); }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    std::string result;
    result.reserve(PBKDF2_SALT_SIZE + AES_IV_SIZE + ciphertext_len);
    result.append(reinterpret_cast<char*>(salt.data()), PBKDF2_SALT_SIZE);
    result.append(reinterpret_cast<char*>(iv), AES_IV_SIZE);
    result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    return result;
}

std::string AesEncryption::aesDecrypt(const std::string& ciphertext, const std::string& key) {
    if (ciphertext.size() <= PBKDF2_SALT_SIZE + AES_IV_SIZE) throw EncryptionError("Ciphertext too short");
    std::array<unsigned char, PBKDF2_SALT_SIZE> salt;
    std::copy(ciphertext.begin(), ciphertext.begin() + PBKDF2_SALT_SIZE, salt.begin());
    auto deriveKeyResult = deriveKey(key, salt);
    const unsigned char* iv = reinterpret_cast<const unsigned char*>(ciphertext.data() + PBKDF2_SALT_SIZE);
    const unsigned char* encrypted_data = iv + AES_IV_SIZE;
    int encrypted_len = ciphertext.size() - PBKDF2_SALT_SIZE - AES_IV_SIZE;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw EncryptionError("Failed to create context");
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, deriveKeyResult.data(), iv) != 1) { EVP_CIPHER_CTX_free(ctx); throw EncryptionError("Init failed"); }
    std::vector<unsigned char> plaintext(encrypted_len);
    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted_data, encrypted_len) != 1) { EVP_CIPHER_CTX_free(ctx); throw EncryptionError("Update failed"); }
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); throw EncryptionError("Final failed"); }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

std::array<unsigned char, AES_KEY_SIZE> AesEncryption::deriveKey(const std::string& password, const std::array<unsigned char, PBKDF2_SALT_SIZE>& salt) {
    std::array<unsigned char, AES_KEY_SIZE> key;
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), PBKDF2_SALT_SIZE, PBKDF2_ITERATIONS, EVP_sha256(), AES_KEY_SIZE, key.data()) != 1) throw EncryptionError("PBKDF2 failed");
    return key;
}

std::array<unsigned char, PBKDF2_SALT_SIZE> AesEncryption::generateSalt() {
    std::array<unsigned char, PBKDF2_SALT_SIZE> salt;
    if (RAND_bytes(salt.data(), PBKDF2_SALT_SIZE) != 1) throw EncryptionError("Failed to generate salt");
    return salt;
}

std::string AesEncryption::encrypt(const std::string& plaintext) {
    return aesEncrypt(plaintext, masterPassword);
}

// similar for others

std::string AesEncryption::decrypt(const std::string& encrypted_text) {
    return aesDecrypt(encrypted_text, masterPassword);
}

std::string AesEncryption::encryptWithSalt(const std::string& plaintext) {
    return encrypt(plaintext); // As per original, no salt for AES
}

std::string AesEncryption::decryptWithSalt(const std::string& encrypted_text) {
    return decrypt(encrypted_text);
}

std::string AesEncryption::computeSha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::string AesEncryption::hash(const std::string& input) {
    return computeSha256(input);
}

void AesEncryption::setMasterPassword(const std::string& password) {
    masterPassword = password;
} 