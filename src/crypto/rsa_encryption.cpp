#include "rsa_encryption.h"
#include <sstream>
#include <stdexcept>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Helper function to throw OpenSSL errors as exceptions
[[noreturn]] void RSAEncryption::throwOpenSSLError(const std::string& message) const {
    char buf[256];
    ERR_error_string(ERR_get_error(), buf);
    throw std::runtime_error(message + ": " + buf);
}

RSAEncryption::RSAEncryption(int keySize)
    : m_pkey(nullptr), m_keySize(keySize) {
    // Keys will be loaded explicitly via loadKeys or generated via generateKeyPair
}

RSAEncryption::~RSAEncryption() {
    if (m_pkey) {
        EVP_PKEY_free(m_pkey);
    }
}

void RSAEncryption::generateKeyPair(int keySize) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) throwOpenSSLError("Failed to create EVP_PKEY_CTX");

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to initialize keygen");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to set RSA key size");
    }

    if (EVP_PKEY_keygen(ctx, &m_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to generate RSA key pair");
    }

    EVP_PKEY_CTX_free(ctx);
}

void RSAEncryption::loadKeys(const std::string& publicKey, const std::string& privateKey) {
    // Validate input parameters
    if (privateKey.empty()) {
        throw std::invalid_argument("Private key cannot be empty");
    }
    
    // Clean up existing key if any
    if (m_pkey) {
        EVP_PKEY_free(m_pkey);
        m_pkey = nullptr;
    }
    
    // In the EVP API, the private key often contains the public key components.
    // We load the private key, and it can be used for both encryption and decryption.
    BIO* bio = BIO_new_mem_buf(privateKey.data(), static_cast<int>(privateKey.size()));
    if (!bio) throwOpenSSLError("Failed to create BIO for private key");

    // First, try to load the private key without a passphrase (unencrypted key)
    m_pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    
    if (!m_pkey && !m_masterPassword.empty()) {
        // If that failed and we have a master password, try with passphrase callback
        BIO_reset(bio);
        
        auto passphraseCb = [](char* buf, int size, int rwflag, void* u) -> int {
            auto* pass = static_cast<std::string*>(u);
            if (!pass || pass->empty() || size < 1) return -1;
            int len = std::min(static_cast<int>(pass->size()), size - 1);
            memcpy(buf, pass->c_str(), len);
            buf[len] = '\0';
            return len;
        };
        
        m_pkey = PEM_read_bio_PrivateKey(bio, nullptr, passphraseCb, &m_masterPassword);
    }
    
    BIO_free(bio);

    if (!m_pkey) {
        throwOpenSSLError("Failed to load private key - check key format and passphrase");
    }
    
    // Validate that the loaded key is actually an RSA key
    if (EVP_PKEY_base_id(m_pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(m_pkey);
        m_pkey = nullptr;
        throw std::invalid_argument("Loaded key is not an RSA key");
    }
    
    // Verify key can be used for encryption/decryption
    EVP_PKEY_CTX* test_ctx = EVP_PKEY_CTX_new(m_pkey, nullptr);
    if (!test_ctx) {
        EVP_PKEY_free(m_pkey);
        m_pkey = nullptr;
        throwOpenSSLError("Failed to create test context for key validation");
    }
    
    if (EVP_PKEY_encrypt_init(test_ctx) <= 0) {
        EVP_PKEY_CTX_free(test_ctx);
        EVP_PKEY_free(m_pkey);
        m_pkey = nullptr;
        throwOpenSSLError("Key validation failed - key cannot be used for encryption");
    }
    
    EVP_PKEY_CTX_free(test_ctx);
}





std::string RSAEncryption::encrypt(const std::string& plaintext) {
    if (!m_pkey) throw std::runtime_error("Key not initialized for encryption");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(m_pkey, nullptr);
    if (!ctx) throwOpenSSLError("Failed to create EVP_PKEY_CTX for encryption");

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to initialize encryption");
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to set RSA padding");
    }

    size_t outLen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to determine encrypted length");
    }

    std::vector<unsigned char> encrypted(outLen);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outLen, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("RSA encryption failed");
    }

    EVP_PKEY_CTX_free(ctx);
    return std::string(encrypted.begin(), encrypted.end());
}

std::string RSAEncryption::decrypt(const std::string& ciphertext) {
    if (!m_pkey) throw std::runtime_error("Key not initialized for decryption");

    auto try_decrypt = [&](int padding) -> std::string {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(m_pkey, nullptr);
        if (!ctx) return "";

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        size_t outLen;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        std::vector<unsigned char> decrypted(outLen);
        if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outLen, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return "";
        }

        EVP_PKEY_CTX_free(ctx);
        return std::string(reinterpret_cast<char*>(decrypted.data()), outLen);
    };

    // Try with modern OAEP padding first
    std::string result = try_decrypt(RSA_PKCS1_OAEP_PADDING);
    if (!result.empty()) {
        return result;
    }

    // Fallback to legacy PKCS1 padding
    result = try_decrypt(RSA_PKCS1_PADDING);
    if (!result.empty()) {
        return result;
    }

    throwOpenSSLError("RSA decryption failed with all supported paddings");
}

void RSAEncryption::setMasterPassword(const std::string& password) {
    m_masterPassword = password;
    // Note: In a real implementation, you might want to use the master password
    // to encrypt/decrypt the private key when storing/loading it.
    // For simplicity, we're just storing it as-is in this example.
}

std::string RSAEncryption::getPublicKey() const {
    if (!m_pkey) return "";

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) throwOpenSSLError("Failed to create BIO for public key export");

    if (PEM_write_bio_PUBKEY(bio, m_pkey) != 1) {
        BIO_free(bio);
        throwOpenSSLError("Failed to write public key to BIO");
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string result(mem->data, mem->length);
    BIO_free(bio);

    return result;
}

std::string RSAEncryption::getPrivateKey() const {
    if (!m_pkey) return "";

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) throwOpenSSLError("Failed to create BIO for private key export");

    EVP_CIPHER* cipher = nullptr;
    if (!m_masterPassword.empty()) {
        cipher = const_cast<EVP_CIPHER*>(EVP_aes_256_cbc());
    }

    if (PEM_write_bio_PrivateKey(
            bio, 
            m_pkey, 
            cipher,
            reinterpret_cast<const unsigned char*>(m_masterPassword.c_str()),
            static_cast<int>(m_masterPassword.length()),
            nullptr, 
            nullptr) != 1) {
        BIO_free(bio);
        throwOpenSSLError("Failed to write private key to BIO");
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string result(mem->data, mem->length);
    BIO_free(bio);

    return result;
}
