#include "rsa_encryption.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sstream>
#include <stdexcept>
#include <vector>

RsaEncryption::RsaEncryption(const std::string& pubKey, const std::string& privKey)
    : publicKey(pubKey), privateKey(privKey), hasPrivateKey(!privKey.empty()) {}

static EVP_PKEY* loadPublicKey(const std::string& pubKey) {
    BIO* bio = BIO_new_mem_buf(pubKey.data(), pubKey.size());
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) throw std::runtime_error("Failed to load RSA public key");
    return pkey;
}

static EVP_PKEY* loadPrivateKey(const std::string& privKey) {
    BIO* bio = BIO_new_mem_buf(privKey.data(), privKey.size());
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) throw std::runtime_error("Failed to load RSA private key");
    return pkey;
}

std::string RsaEncryption::encrypt(const std::string& plaintext) {
    EVP_PKEY* pkey = loadPublicKey(publicKey);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_encrypt_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set RSA padding");
    }
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, (const unsigned char*)plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_encrypt (size) failed");
    }
    std::vector<unsigned char> outbuf(outlen);
    if (EVP_PKEY_encrypt(ctx, outbuf.data(), &outlen, (const unsigned char*)plaintext.data(), plaintext.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_encrypt failed");
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return std::string((char*)outbuf.data(), outlen);
}

std::string RsaEncryption::decrypt(const std::string& encrypted_text) {
    if (!hasPrivateKey) throw std::runtime_error("No private key for decryption");
    EVP_PKEY* pkey = loadPrivateKey(privateKey);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_decrypt_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to set RSA padding");
    }
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, (const unsigned char*)encrypted_text.data(), encrypted_text.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_decrypt (size) failed");
    }
    std::vector<unsigned char> outbuf(outlen);
    if (EVP_PKEY_decrypt(ctx, outbuf.data(), &outlen, (const unsigned char*)encrypted_text.data(), encrypted_text.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_decrypt failed");
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return std::string((char*)outbuf.data(), outlen);
}

std::string RsaEncryption::encryptWithSalt(const std::string& plaintext) {
    // For demo, just call encrypt (no salt)
    return encrypt(plaintext);
}

std::string RsaEncryption::decryptWithSalt(const std::string& encrypted_text) {
    return decrypt(encrypted_text);
}

std::string RsaEncryption::hash(const std::string& input) {
    // For RSA, just return a SHA256 hash for demonstration
    unsigned char hash[32];
    SHA256((const unsigned char*)input.data(), input.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < 32; ++i) {
        oss << std::hex << (int)hash[i];
    }
    return oss.str();
}

std::pair<std::string, std::string> RsaEncryption::generateKeyPair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX for keygen");
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen_init failed");
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set RSA keygen bits");
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }
    EVP_PKEY_CTX_free(ctx);
    // Write public key
    BIO* pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub, pkey);
    char* pubData = nullptr;
    long pubLen = BIO_get_mem_data(pub, &pubData);
    std::string pubKey(pubData, pubLen);
    BIO_free(pub);
    // Write private key
    BIO* priv = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(priv, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* privData = nullptr;
    long privLen = BIO_get_mem_data(priv, &privData);
    std::string privKey(privData, privLen);
    BIO_free(priv);
    EVP_PKEY_free(pkey);
    return {pubKey, privKey};
} 