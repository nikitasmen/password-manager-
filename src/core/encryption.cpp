#include "./encryption.h"
#include "../crypto/cipher_context_raii.h"
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <random>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

using namespace std;

// CipherContextRAII implementation has been moved to cipher_context_raii.h/cpp

// Helper function to convert bytes to hex
static string bytesToHex(const vector<unsigned char>& bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    for(unsigned char b : bytes) {
        ss << setw(2) << static_cast<unsigned>(b);
    }
    return ss.str();
}

// Helper function to convert hex string to bytes
static vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Generate random bytes
vector<unsigned char> generateRandomBytes(size_t length) {
    vector<unsigned char> bytes(length);
    if (RAND_bytes(bytes.data(), static_cast<int>(length)) != 1) {
        throw runtime_error("Failed to generate random bytes");
    }
    return bytes;
}

// Encryption class implementation
Encryption::Encryption(EncryptionType algorithm, 
                     const vector<int>& taps,
                     const vector<int>& initState,
                     const string& password)
    : algorithm_(algorithm), taps_(taps), 
      initialState_(initState), masterPassword_(password) {
    // Initialize OpenSSL algorithms
    OpenSSL_add_all_algorithms();
    
    // If no initial state is provided for LFSR, use a default one
    if (algorithm_ == EncryptionType::LFSR && initialState_.empty()) {
        initialState_ = {1, 0, 1, 1, 0, 1, 0, 1}; // Default initial state
    }
    
    // If no taps are provided for LFSR, use a default one
    if (algorithm_ == EncryptionType::LFSR && taps_.empty()) {
        taps_ = {0, 2}; // Default taps for LFSR
    }
}

void Encryption::setMasterPassword(const string& password) {
    masterPassword_ = password;
}

string Encryption::encrypt(const string& plaintext) {
    if (masterPassword_.empty()) {
        throw runtime_error("Master password not set");
    }
    
    try {
        switch (algorithm_) {
            case EncryptionType::AES:
                return aesEncrypt(plaintext, masterPassword_);
            case EncryptionType::LFSR:
                return lfsrProcess(plaintext);
            default:
                throw runtime_error("Unsupported encryption algorithm");
        }
    } catch (const exception& e) {
        throw runtime_error(string("Encryption failed: ") + e.what());
    }
}

string Encryption::decrypt(const string& ciphertext) {
    if (masterPassword_.empty()) {
        throw runtime_error("Master password not set");
    }
    
    try {
        switch (algorithm_) {
            case EncryptionType::AES:
                return aesDecrypt(ciphertext, masterPassword_);
            case EncryptionType::LFSR:
                return lfsrProcess(ciphertext); // LFSR is symmetric
            default:
                throw runtime_error("Unsupported encryption algorithm");
        }
    } catch (const exception& e) {
        throw runtime_error(string("Decryption failed: ") + e.what());
    }
}

// Salt-based encryption/decryption helpers
string Encryption::encryptWithSalt(const string& plaintext) {
    if (algorithm_ == EncryptionType::LFSR) {
        // For LFSR, we'll use the salt to modify the initial state
        return lfsrProcess(plaintext);
    } else {
        // For AES, we already handle salt in the encryption process
        return encrypt(plaintext);
    }
}

string Encryption::decryptWithSalt(const string& ciphertext) {
    if (algorithm_ == EncryptionType::LFSR) {
        // For LFSR, decryption is the same as encryption
        return lfsrProcess(ciphertext);
    } else {
        // For AES, we handle salt in the decryption process
        return decrypt(ciphertext);
    }
}

// LFSR Implementation
string Encryption::lfsrProcess(const string& input) {
    if (taps_.empty() || initialState_.empty()) {
        throw runtime_error("LFSR not properly initialized");
    }

    vector<int> state = initialState_;
    string result;
    result.reserve(input.size());

    for (char c : input) {
        // XOR the tap bits
        int feedback = 0;
        for (int tap : taps_) {
            if (tap >= 0 && tap < state.size()) {
                feedback ^= state[tap];
            }
        }

        // Get the output bit (MSB of the state)
        int output = state.back();
        
        // Shift state right and set MSB to feedback
        for (int i = state.size() - 1; i > 0; --i) {
            state[i] = state[i-1];
        }
        state[0] = feedback;

        // XOR the input byte with the output bit
        result.push_back(c ^ (output & 0xFF));
    }

    return result;
}

// AES Implementation
string Encryption::aesEncrypt(const string& plaintext, const string& key) {
    // Generate a random IV
    array<unsigned char, AES_IV_SIZE> iv;
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        throw runtime_error("Failed to generate IV");
    }

    // Generate salt and derive key
    auto salt = generateSalt();
    auto derivedKey = deriveKey(key, salt);

    // Initialize context
    CipherContextRAII ctx;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                          derivedKey.data(), iv.data()) != 1) {
        throw runtime_error("Failed to initialize encryption");
    }

    // Encrypt
    vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                         reinterpret_cast<const unsigned char*>(plaintext.data()), 
                         plaintext.size()) != 1) {
        throw runtime_error("Encryption failed");
    }
    int ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        throw runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    // Combine salt, IV, and ciphertext
    string result;
    result.reserve(salt.size() + iv.size() + ciphertext.size());
    result.append(reinterpret_cast<const char*>(salt.data()), salt.size());
    result.append(reinterpret_cast<const char*>(iv.data()), iv.size());
    result.append(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());

    return result;
}

string Encryption::aesDecrypt(const string& ciphertext, const string& key) {
    // Check minimum size (salt + IV)
    if (ciphertext.size() < PBKDF2_SALT_SIZE + AES_IV_SIZE) {
        throw runtime_error("Invalid ciphertext format");
    }

    // Extract salt, IV, and actual ciphertext
    array<unsigned char, PBKDF2_SALT_SIZE> salt;
    copy_n(ciphertext.begin(), salt.size(), salt.begin());

    array<unsigned char, AES_IV_SIZE> iv;
    copy_n(ciphertext.begin() + salt.size(), iv.size(), iv.begin());

    string encrypted(ciphertext.begin() + salt.size() + iv.size(), ciphertext.end());

    // Derive key
    auto derivedKey = deriveKey(key, salt);

    // Initialize context
    CipherContextRAII ctx;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                          derivedKey.data(), iv.data()) != 1) {
        throw runtime_error("Failed to initialize decryption");
    }

    // Decrypt
    vector<unsigned char> plaintext(encrypted.size() + AES_BLOCK_SIZE);
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                         reinterpret_cast<const unsigned char*>(encrypted.data()),
                         encrypted.size()) != 1) {
        throw runtime_error("Decryption failed");
    }
    int plaintext_len = len;

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        throw runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    return string(plaintext.begin(), plaintext.end());
}

array<unsigned char, PBKDF2_SALT_SIZE> Encryption::generateSalt() {
    array<unsigned char, PBKDF2_SALT_SIZE> salt;
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        throw runtime_error("Failed to generate salt");
    }
    return salt;
}

array<unsigned char, AES_KEY_SIZE> Encryption::deriveKey(
    const string& password, 
    const array<unsigned char, PBKDF2_SALT_SIZE>& salt) {
    
    array<unsigned char, AES_KEY_SIZE> key;
    
    if (PKCS5_PBKDF2_HMAC(
        password.data(), static_cast<int>(password.size()),
        salt.data(), salt.size(),
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        key.size(), key.data()) != 1) {
        throw runtime_error("Failed to derive key");
    }
    
    return key;
}

// Static methods for master password encryption/decryption
string Encryption::decryptMasterPassword(EncryptionType type, 
                                       const vector<int>& taps, 
                                       const vector<int>& initState, 
                                       const string& encrypted, 
                                       const string& masterPassword) {
    try {
        Encryption decryptor(type, taps, initState, masterPassword);
        // For master password, we use decryptWithSalt which handles the salt properly
        return decryptor.decryptWithSalt(encrypted);
    } catch (const exception& e) {
        throw runtime_error(string("Failed to decrypt master password: ") + e.what());
    }
}

string Encryption::encryptMasterPassword(EncryptionType type, 
                                       const vector<int>& taps, 
                                       const vector<int>& initState, 
                                       const string& masterPassword) {
    try {
        Encryption encryptor(type, taps, initState, masterPassword);
        // For master password, we use encryptWithSalt which adds a random salt
        return encryptor.encryptWithSalt(masterPassword);
    } catch (const exception& e) {
        throw runtime_error(string("Failed to encrypt master password: ") + e.what());
    }
}
