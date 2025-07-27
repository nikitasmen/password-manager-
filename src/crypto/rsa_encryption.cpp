#include "rsa_encryption.h"
#include <sstream>
#include <stdexcept>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Helper function to throw OpenSSL errors as exceptions
[[noreturn]] static void throwOpenSSLError(const std::string& message) {
    char buf[256];
    ERR_error_string(ERR_get_error(), buf);
    throw std::runtime_error(message + ": " + buf);
}

RSAEncryption::RSAEncryption(int keySize, const std::string& publicKey, 
                           const std::string& privateKey)
    : m_rsaPublicKey(nullptr), m_rsaPrivateKey(nullptr), m_keySize(keySize) {
    
    // Initialize OpenSSL if not already initialized
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    if (!publicKey.empty() && !privateKey.empty()) {
        loadKeys(publicKey, privateKey);
    } else {
        generateKeyPair(keySize);
    }
}

RSAEncryption::~RSAEncryption() {
    if (m_rsaPublicKey) {
        RSA_free(m_rsaPublicKey);
    }
    if (m_rsaPrivateKey) {
        RSA_free(m_rsaPrivateKey);
    }
    EVP_cleanup();
    ERR_free_strings();
}

void RSAEncryption::generateKeyPair(int keySize) {
    // Generate RSA key pair
    BIGNUM* bne = BN_new();
    if (!bne) throwOpenSSLError("Failed to create BIGNUM");
    
    if (BN_set_word(bne, RSA_F4) != 1) {
        BN_free(bne);
        throwOpenSSLError("Failed to set RSA exponent");
    }
    
    RSA* rsa = RSA_new();
    if (!rsa) {
        BN_free(bne);
        throwOpenSSLError("Failed to create RSA structure");
    }
    
    if (RSA_generate_key_ex(rsa, keySize, bne, nullptr) != 1) {
        RSA_free(rsa);
        BN_free(bne);
        throwOpenSSLError("Failed to generate RSA key pair");
    }
    
    BN_free(bne);
    
    // Duplicate the key for public and private use
    m_rsaPublicKey = RSAPublicKey_dup(rsa);
    m_rsaPrivateKey = RSAPrivateKey_dup(rsa);
    RSA_free(rsa);
    
    if (!m_rsaPublicKey || !m_rsaPrivateKey) {
        if (m_rsaPublicKey) RSA_free(m_rsaPublicKey);
        if (m_rsaPrivateKey) RSA_free(m_rsaPrivateKey);
        m_rsaPublicKey = m_rsaPrivateKey = nullptr;
        throwOpenSSLError("Failed to duplicate RSA keys");
    }
}

void RSAEncryption::loadKeys(const std::string& publicKey, const std::string& privateKey) {
    BIO* bio = BIO_new_mem_buf(publicKey.data(), static_cast<int>(publicKey.size()));
    if (!bio) throwOpenSSLError("Failed to create BIO for public key");
    
    m_rsaPublicKey = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!m_rsaPublicKey) {
        throwOpenSSLError("Failed to load public key");
    }
    
    bio = BIO_new_mem_buf(privateKey.data(), static_cast<int>(privateKey.size()));
    if (!bio) {
        RSA_free(m_rsaPublicKey);
        m_rsaPublicKey = nullptr;
        throwOpenSSLError("Failed to create BIO for private key");
    }
    
    auto passphraseCb = [](char* buf, int size, int rwflag, void* u) -> int {
        const std::string* pass = static_cast<const std::string*>(u);
        if (!pass || pass->empty() || size < 1) return -1;
        int len = std::min(static_cast<int>(pass->size()), size - 1);
        memcpy(buf, pass->c_str(), len);
        buf[len] = '\0';
        return len;
    };
    
    m_rsaPrivateKey = PEM_read_bio_RSAPrivateKey(bio, nullptr, passphraseCb, const_cast<std::string*>(&m_masterPassword));
    BIO_free(bio);
    
    if (!m_rsaPrivateKey) {
        RSA_free(m_rsaPublicKey);
        m_rsaPublicKey = nullptr;
        throwOpenSSLError("Failed to load private key");
    }
}

std::string RSAEncryption::rsaEncrypt(const std::string& plaintext, RSA* rsaKey) {
    if (!rsaKey) {
        throw std::runtime_error("Invalid RSA key for encryption");
    }
    
    const int rsaSize = RSA_size(rsaKey);
    std::vector<unsigned char> encrypted(rsaSize);
    
    int result = RSA_public_encrypt(
        static_cast<int>(plaintext.size()),
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        encrypted.data(),
        rsaKey,
        RSA_PKCS1_OAEP_PADDING
    );
    
    if (result == -1) {
        throwOpenSSLError("RSA encryption failed");
    }
    
    return std::string(encrypted.begin(), encrypted.begin() + result);
}

std::string RSAEncryption::rsaDecrypt(const std::string& ciphertext, RSA* rsaKey) {
    if (!rsaKey) {
        throw std::runtime_error("Invalid RSA key for decryption");
    }
    
    const int rsaSize = RSA_size(rsaKey);
    std::vector<unsigned char> decrypted(rsaSize);
    
    int result = RSA_private_decrypt(
        static_cast<int>(ciphertext.size()),
        reinterpret_cast<const unsigned char*>(ciphertext.data()),
        decrypted.data(),
        rsaKey,
        RSA_PKCS1_OAEP_PADDING
    );
    
    if (result == -1) {
        throwOpenSSLError("RSA decryption failed");
    }
    
    return std::string(decrypted.begin(), decrypted.begin() + result);
}

std::string RSAEncryption::encrypt(const std::string& plaintext) {
    try {
        return rsaEncrypt(plaintext, m_rsaPublicKey);
    } catch (const std::exception& e) {
        throw EncryptionError(std::string("Encryption failed: ") + e.what());
    }
}

std::string RSAEncryption::decrypt(const std::string& ciphertext) {
    try {
        return rsaDecrypt(ciphertext, m_rsaPrivateKey);
    } catch (const std::exception& e) {
        throw EncryptionError(std::string("Decryption failed: ") + e.what());
    }
}

void RSAEncryption::setMasterPassword(const std::string& password) {
    m_masterPassword = password;
    // Note: In a real implementation, you might want to use the master password
    // to encrypt/decrypt the private key when storing/loading it.
    // For simplicity, we're just storing it as-is in this example.
}

std::string RSAEncryption::getPublicKey() const {
    if (!m_rsaPublicKey) {
        return "";
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throwOpenSSLError("Failed to create BIO for public key export");
    }
    
    if (PEM_write_bio_RSA_PUBKEY(bio, m_rsaPublicKey) != 1) {
        BIO_free(bio);
        throwOpenSSLError("Failed to write public key");
    }
    
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string result(mem->data, mem->length);
    BIO_free(bio);
    
    return result;
}

std::string RSAEncryption::getPrivateKey() const {
    if (!m_rsaPrivateKey) {
        return "";
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throwOpenSSLError("Failed to create BIO for private key export");
    }
    
    // Use a default passphrase callback if needed
    auto passphraseCb = [](char* buf, int size, int rwflag, void* u) -> int {
        const std::string* pass = static_cast<const std::string*>(u);
        if (!pass || pass->empty() || size < 1) return 0;
        int len = std::min(static_cast<int>(pass->size()), size - 1);
        memcpy(buf, pass->c_str(), len);
        buf[len] = '\0';
        return len;
    };
    
    if (m_masterPassword.empty()) {
        if (PEM_write_bio_RSAPrivateKey(bio, m_rsaPrivateKey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            BIO_free(bio);
            throwOpenSSLError("Failed to write private key");
        }
    } else {
        if (PEM_write_bio_RSAPrivateKey(
                bio, 
                m_rsaPrivateKey, 
                EVP_aes_256_cbc(),
                reinterpret_cast<const unsigned char*>(m_masterPassword.c_str()),
                static_cast<int>(m_masterPassword.length()),
                nullptr,
                nullptr) != 1) {
            BIO_free(bio);
            throwOpenSSLError("Failed to write private key");
        }
    }
    
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string result(mem->data, mem->length);
    BIO_free(bio);
    
    return result;
}
