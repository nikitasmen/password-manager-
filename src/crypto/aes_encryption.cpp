#include "aes_encryption.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>

#include "cipher_context_raii.h"

// CipherContextRAII implementation has been moved to cipher_context_raii.h/cpp

// AESEncryption implementation
AESEncryption::AESEncryption() {
    // Initialize OpenSSL if needed
    OpenSSL_add_all_algorithms();
}

void AESEncryption::setMasterPassword(const std::string& password) {
    std::lock_guard<std::mutex> lock(mutex_);
    masterPassword_ = password;
}

std::vector<unsigned char> AESEncryption::generateSalt() {
    std::vector<unsigned char> salt(SALT_SIZE);
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        throw EncryptionError("Failed to generate random salt");
    }
    return salt;
}

std::vector<unsigned char> AESEncryption::deriveKey(const std::vector<unsigned char>& salt) {
    if (masterPassword_.empty()) {
        throw EncryptionError("Master password not set");
    }

    std::vector<unsigned char> key(KEY_SIZE);

    int result = PKCS5_PBKDF2_HMAC(masterPassword_.c_str(),
                                   static_cast<int>(masterPassword_.length()),
                                   salt.data(),
                                   static_cast<int>(salt.size()),
                                   ITERATIONS,
                                   EVP_sha256(),
                                   static_cast<int>(key.size()),
                                   key.data());

    if (result != 1) {
        throw EncryptionError("Failed to derive key from password");
    }

    return key;
}

std::string AESEncryption::encrypt(const std::string& plaintext) {
    if (plaintext.empty()) {
        return "";
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Generate random salt and IV
    auto salt = generateSalt();
    std::vector<unsigned char> iv(IV_SIZE);
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        throw EncryptionError("Failed to generate IV");
    }

    // Derive key using salt
    auto key = deriveKey(salt);

    // Initialize encryption context
    CipherContextRAII ctx;
    if (!ctx.get()) {
        throw EncryptionError("Failed to create encryption context");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        throw EncryptionError("Failed to initialize encryption");
    }

    // Encrypt the data
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len;
    int ciphertext_len;

    if (EVP_EncryptUpdate(ctx.get(),
                          ciphertext.data(),
                          &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1) {
        throw EncryptionError("Encryption failed");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
        throw EncryptionError("Final encryption failed");
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    // Combine salt + iv + ciphertext
    std::vector<unsigned char> result;
    result.reserve(salt.size() + iv.size() + ciphertext.size());
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    return std::string(result.begin(), result.end());
}

std::string AESEncryption::decrypt(const std::string& ciphertext) {
    if (ciphertext.empty()) {
        return "";
    }

    // Check minimum size (must have at least salt + iv)
    const size_t min_size = SALT_SIZE + IV_SIZE;
    if (ciphertext.size() < min_size) {
        std::cerr << "AES Decrypt Error: Ciphertext too short. Size: " << ciphertext.size()
                  << ", Required: " << min_size << " (SALT: " << SALT_SIZE << " + IV: " << IV_SIZE << ")" << std::endl;
        throw EncryptionError("Ciphertext too short to contain salt and IV");
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Extract salt, IV and actual ciphertext
    auto it = ciphertext.begin();
    std::vector<unsigned char> salt(it, it + SALT_SIZE);
    it += SALT_SIZE;
    std::vector<unsigned char> iv(it, it + IV_SIZE);
    it += IV_SIZE;
    std::vector<unsigned char> encrypted_data(it, ciphertext.end());

    // Derive key using salt
    auto key = deriveKey(salt);

    // Initialize decryption context
    CipherContextRAII ctx;
    if (!ctx.get()) {
        throw EncryptionError("Failed to create decryption context");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        throw EncryptionError("Failed to initialize decryption");
    }

    // Decrypt the data
    std::vector<unsigned char> plaintext(encrypted_data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len;
    int plaintext_len;

    if (EVP_DecryptUpdate(
            ctx.get(), plaintext.data(), &len, encrypted_data.data(), static_cast<int>(encrypted_data.size())) != 1) {
        throw EncryptionError("Decryption failed");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1) {
        throw EncryptionError("Final decryption failed - invalid password or corrupted data");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    return std::string(plaintext.begin(), plaintext.end());
}
