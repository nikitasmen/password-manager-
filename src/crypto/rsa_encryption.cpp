#include "rsa_encryption.h"
#include <sstream>
#include <stdexcept>
#include <iomanip>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>

// Helper function to convert bytes to hex string
static std::string bytesToHex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return ss.str();
}

// Helper function to convert hex string to bytes
static std::string hexToBytes(const std::string& hex) {
    std::string result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

[[noreturn]] void RSAEncryption::throwOpenSSLError(const std::string& message) const {
    char buf[256];
    ERR_error_string(ERR_get_error(), buf);
    throw std::runtime_error(message + ": " + buf);
}

RSAEncryption::RSAEncryption(int keySize)
    : m_pkey(nullptr), m_keySize(keySize), m_initialized(false) {
    // Generate random salt for key derivation
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        throwOpenSSLError("Failed to generate salt");
    }
    m_keySalt = std::string(reinterpret_cast<char*>(salt), sizeof(salt));
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
    m_keySize = keySize;
    m_initialized = true;
}

std::string RSAEncryption::deriveKEK(const std::string& masterPassword, const std::string& salt) const {
    const int iterations = 100000; // PBKDF2 iterations
    const int keyLength = 32; // 256 bits
    
    unsigned char derivedKey[32];
    if (PKCS5_PBKDF2_HMAC(masterPassword.c_str(), masterPassword.length(),
                          reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
                          iterations, EVP_sha256(), keyLength, derivedKey) != 1) {
        throwOpenSSLError("Failed to derive key encryption key");
    }
    
    return std::string(reinterpret_cast<char*>(derivedKey), keyLength);
}

std::string RSAEncryption::encryptPrivateKey() const {
    if (!m_pkey || m_masterPassword.empty()) {
        throw std::runtime_error("Cannot encrypt private key: missing key or master password");
    }
    
    // Export private key to memory
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) throwOpenSSLError("Failed to create BIO");
    
    if (PEM_write_bio_PrivateKey(bio, m_pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        throwOpenSSLError("Failed to export private key");
    }
    
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string privateKeyPEM(mem->data, mem->length);
    BIO_free(bio);
    
    // Derive encryption key from master password
    std::string kek = deriveKEK(m_masterPassword, m_keySalt);
    
    // Encrypt private key with AES-256-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throwOpenSSLError("Failed to create cipher context");
    
    // Generate random IV
    unsigned char iv[12]; // GCM recommended IV size
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to generate IV");
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                          reinterpret_cast<const unsigned char*>(kek.c_str()), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to initialize encryption");
    }
    
    std::vector<unsigned char> encrypted(privateKeyPEM.length() + 16);
    int len;
    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len,
                         reinterpret_cast<const unsigned char*>(privateKeyPEM.c_str()),
                         privateKeyPEM.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to encrypt private key");
    }
    
    int finalLen;
    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to finalize encryption");
    }
    
    // Get authentication tag
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to get authentication tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Serialize: salt + iv + encrypted_data + auth_tag
    std::string result;
    result += bytesToHex(reinterpret_cast<const unsigned char*>(m_keySalt.c_str()), m_keySalt.length()) + "|";
    result += bytesToHex(iv, sizeof(iv)) + "|";
    result += bytesToHex(encrypted.data(), len + finalLen) + "|";
    result += bytesToHex(tag, sizeof(tag));
    
    return result;
}

void RSAEncryption::decryptPrivateKey(const std::string& encryptedData) {
    if (m_masterPassword.empty()) {
        throw std::runtime_error("Master password required to decrypt private key");
    }
    
    // Parse serialized data: salt|iv|encrypted_data|auth_tag
    std::vector<std::string> parts;
    std::stringstream ss(encryptedData);
    std::string part;
    while (std::getline(ss, part, '|')) {
        parts.push_back(part);
    }
    
    if (parts.size() != 4) {
        throw std::runtime_error("Invalid encrypted private key format");
    }
    
    std::string salt = hexToBytes(parts[0]);
    std::string iv = hexToBytes(parts[1]);
    std::string encrypted = hexToBytes(parts[2]);
    std::string authTag = hexToBytes(parts[3]);
    
    // Derive decryption key
    std::string kek = deriveKEK(m_masterPassword, salt);
    
    // Decrypt private key
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throwOpenSSLError("Failed to create cipher context");
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                          reinterpret_cast<const unsigned char*>(kek.c_str()),
                          reinterpret_cast<const unsigned char*>(iv.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to initialize decryption");
    }
    
    std::vector<unsigned char> decrypted(encrypted.length());
    int len;
    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len,
                         reinterpret_cast<const unsigned char*>(encrypted.c_str()),
                         encrypted.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to decrypt private key");
    }
    
    // Set authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, authTag.length(),
                           const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(authTag.c_str()))) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to set authentication tag");
    }
    
    int finalLen;
    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to verify authentication or decrypt private key");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Load decrypted private key
    std::string privateKeyPEM(reinterpret_cast<char*>(decrypted.data()), len + finalLen);
    BIO* bio = BIO_new_mem_buf(privateKeyPEM.data(), privateKeyPEM.length());
    if (!bio) throwOpenSSLError("Failed to create BIO for private key");
    
    m_pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!m_pkey) {
        throwOpenSSLError("Failed to load decrypted private key");
    }
    
    m_initialized = true;
}

void RSAEncryption::setMasterPassword(const std::string& password) {
    m_masterPassword = password;
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

std::string RSAEncryption::getEncryptedPrivateKeyData() const {
    return encryptPrivateKey();
}

void RSAEncryption::loadKeys(const std::string& publicKey, const std::string& encryptedPrivateData) {
    if (m_pkey) {
        EVP_PKEY_free(m_pkey);
        m_pkey = nullptr;
    }
    
    // Decrypt and load private key
    decryptPrivateKey(encryptedPrivateData);
    m_initialized = true;
}

bool RSAEncryption::isInitialized() const {
    return m_initialized && m_pkey != nullptr;
}

std::string RSAEncryption::generateAESKey() const {
    unsigned char key[32]; // 256 bits
    if (RAND_bytes(key, sizeof(key)) != 1) {
        throwOpenSSLError("Failed to generate AES key");
    }
    return std::string(reinterpret_cast<char*>(key), sizeof(key));
}

std::string RSAEncryption::encryptAESKeyWithRSA(const std::string& aesKey) const {
    if (!m_pkey) throw std::runtime_error("RSA key not initialized");
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(m_pkey, nullptr);
    if (!ctx) throwOpenSSLError("Failed to create EVP_PKEY_CTX for RSA encryption");
    
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to initialize RSA encryption");
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to set RSA padding");
    }
    
    size_t outLen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outLen,
                        reinterpret_cast<const unsigned char*>(aesKey.c_str()),
                        aesKey.length()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to determine RSA encrypted length");
    }
    
    std::vector<unsigned char> encrypted(outLen);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outLen,
                        reinterpret_cast<const unsigned char*>(aesKey.c_str()),
                        aesKey.length()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("RSA encryption of AES key failed");
    }
    
    EVP_PKEY_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(encrypted.data()), outLen);
}

std::string RSAEncryption::decryptAESKeyWithRSA(const std::string& encryptedAESKey) const {
    if (!m_pkey) throw std::runtime_error("RSA key not initialized");
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(m_pkey, nullptr);
    if (!ctx) throwOpenSSLError("Failed to create EVP_PKEY_CTX for RSA decryption");
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to initialize RSA decryption");
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to set RSA padding");
    }
    
    size_t outLen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outLen,
                        reinterpret_cast<const unsigned char*>(encryptedAESKey.c_str()),
                        encryptedAESKey.length()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("Failed to determine RSA decrypted length");
    }
    
    std::vector<unsigned char> decrypted(outLen);
    if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outLen,
                        reinterpret_cast<const unsigned char*>(encryptedAESKey.c_str()),
                        encryptedAESKey.length()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOpenSSLError("RSA decryption of AES key failed");
    }
    
    EVP_PKEY_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(decrypted.data()), outLen);
}

RSAEncryption::HybridData RSAEncryption::encryptWithAES(const std::string& plaintext, const std::string& aesKey) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throwOpenSSLError("Failed to create AES cipher context");
    
    // Generate random IV
    unsigned char iv[12]; // GCM recommended IV size
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to generate AES IV");
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                          reinterpret_cast<const unsigned char*>(aesKey.c_str()), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to initialize AES encryption");
    }
    
    std::vector<unsigned char> encrypted(plaintext.length() + 16);
    int len;
    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len,
                         reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                         plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to encrypt data with AES");
    }
    
    int finalLen;
    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to finalize AES encryption");
    }
    
    // Get authentication tag
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to get AES authentication tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    HybridData result;
    result.iv = std::string(reinterpret_cast<char*>(iv), sizeof(iv));
    result.encryptedData = std::string(reinterpret_cast<char*>(encrypted.data()), len + finalLen);
    result.authTag = std::string(reinterpret_cast<char*>(tag), sizeof(tag));
    
    return result;
}

std::string RSAEncryption::decryptWithAES(const HybridData& data, const std::string& aesKey) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throwOpenSSLError("Failed to create AES cipher context");
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                          reinterpret_cast<const unsigned char*>(aesKey.c_str()),
                          reinterpret_cast<const unsigned char*>(data.iv.c_str())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to initialize AES decryption");
    }
    
    std::vector<unsigned char> decrypted(data.encryptedData.length());
    int len;
    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len,
                         reinterpret_cast<const unsigned char*>(data.encryptedData.c_str()),
                         data.encryptedData.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to decrypt data with AES");
    }
    
    // Set authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, data.authTag.length(),
                           const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(data.authTag.c_str()))) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to set AES authentication tag");
    }
    
    int finalLen;
    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throwOpenSSLError("Failed to verify AES authentication or decrypt data");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(decrypted.data()), len + finalLen);
}

std::string RSAEncryption::serializeHybridData(const HybridData& data) const {
    std::string result;
    result += bytesToHex(reinterpret_cast<const unsigned char*>(data.encryptedAESKey.c_str()), data.encryptedAESKey.length()) + "|";
    result += bytesToHex(reinterpret_cast<const unsigned char*>(data.iv.c_str()), data.iv.length()) + "|";
    result += bytesToHex(reinterpret_cast<const unsigned char*>(data.encryptedData.c_str()), data.encryptedData.length()) + "|";
    result += bytesToHex(reinterpret_cast<const unsigned char*>(data.authTag.c_str()), data.authTag.length());
    return result;
}

RSAEncryption::HybridData RSAEncryption::deserializeHybridData(const std::string& serialized) const {
    std::vector<std::string> parts;
    std::stringstream ss(serialized);
    std::string part;
    while (std::getline(ss, part, '|')) {
        parts.push_back(part);
    }
    
    if (parts.size() != 4) {
        throw std::runtime_error("Invalid hybrid data format");
    }
    
    HybridData result;
    result.encryptedAESKey = hexToBytes(parts[0]);
    result.iv = hexToBytes(parts[1]);
    result.encryptedData = hexToBytes(parts[2]);
    result.authTag = hexToBytes(parts[3]);
    
    return result;
}

std::string RSAEncryption::encrypt(const std::string& plaintext) {
    if (!isInitialized()) {
        throw std::runtime_error("RSA key not initialized for encryption");
    }
    
    // Generate random AES key
    std::string aesKey = generateAESKey();
    
    // Encrypt data with AES
    HybridData hybridData = encryptWithAES(plaintext, aesKey);
    
    // Encrypt AES key with RSA
    hybridData.encryptedAESKey = encryptAESKeyWithRSA(aesKey);
    
    // Serialize and return
    return serializeHybridData(hybridData);
}

std::string RSAEncryption::decrypt(const std::string& ciphertext) {
    if (!isInitialized()) {
        throw std::runtime_error("RSA key not initialized for decryption");
    }
    
    // Deserialize hybrid data
    HybridData hybridData = deserializeHybridData(ciphertext);
    
    // Decrypt AES key with RSA
    std::string aesKey = decryptAESKeyWithRSA(hybridData.encryptedAESKey);
    
    // Decrypt data with AES
    return decryptWithAES(hybridData, aesKey);
}