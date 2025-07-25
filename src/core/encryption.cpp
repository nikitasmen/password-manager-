#include "./encryption.h"
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

// CipherContextRAII implementation
CipherContextRAII::CipherContextRAII() : ctx_(EVP_CIPHER_CTX_new()) {
    if (!ctx_) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX");
    }
}

CipherContextRAII::~CipherContextRAII() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
        ctx_ = nullptr;
    }
}

CipherContextRAII::CipherContextRAII(CipherContextRAII&& other) noexcept 
    : ctx_(other.ctx_) {
    other.ctx_ = nullptr;
}

CipherContextRAII& CipherContextRAII::operator=(CipherContextRAII&& other) noexcept {
    if (this != &other) {
        if (ctx_) {
            EVP_CIPHER_CTX_free(ctx_);
        }
        ctx_ = other.ctx_;
        other.ctx_ = nullptr;
    }
    return *this;
}

// Helper function to convert bytes to hex
static string bytesToHex(const vector<unsigned char>& bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    for (unsigned char byte : bytes) {
        ss << setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Generate random bytes
static vector<unsigned char> generateRandomBytes(size_t length) {
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
    : taps_(taps), 
      initialState_(initState), 
      masterPassword_(password),
      algorithm_(algorithm) {
    // Validate LFSR parameters if using LFSR
    if (algorithm_ == EncryptionType::LFSR) {
        if (taps_.empty() || initialState_.empty()) {
            throw runtime_error("LFSR requires taps and initial state");
        }
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
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
        throw runtime_error("Encryption failed: " + string(e.what()));
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
        throw runtime_error("Decryption failed: " + string(e.what()));
    }
}

// Salt-based encryption/decryption helpers
string Encryption::encryptWithSalt(const string& plaintext) {
    // Generate a random salt
    auto salt = generateSalt();
    string salt_str(salt.begin(), salt.end());
    
    // Encrypt with salt prepended to plaintext
    return encrypt(salt_str + plaintext);
}

string Encryption::decryptWithSalt(const string& ciphertext) {
    // Decrypt the data
    string decrypted = decrypt(ciphertext);
    
    // Remove the salt (first PBKDF2_SALT_SIZE bytes)
    if (decrypted.length() > PBKDF2_SALT_SIZE) {
        return decrypted.substr(PBKDF2_SALT_SIZE);
    }
    
    throw runtime_error("Invalid ciphertext format: too short to contain salt");
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

// Helper function to convert bytes to hex string
static std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Helper function to convert hex string to bytes
static std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

void Encryption::createImplementation() {
    implementation_ = EncryptionFactory::createForMasterPassword(
        algorithm_, 
        masterPassword_, 
        taps_, 
        initialState_);
}

Encryption::Encryption(EncryptionType algorithm, const std::vector<int>& taps, 
                      const std::vector<int>& init_state, const std::string& password)
    : taps_(taps), initialState_(init_state), masterPassword_(password), algorithm_(algorithm) {
    
    if (algorithm_ == EncryptionType::LFSR) {
        if (init_state.empty()) {
            throw EncryptionError("Initial state cannot be empty for LFSR encryption");
        }
        
        if (!taps.empty() && *std::max_element(taps.begin(), taps.end()) >= init_state.size()) {
            throw EncryptionError("Tap positions exceed initial state size");
        }
    }
    
    createImplementation();
}

void Encryption::setAlgorithm(EncryptionType newAlgorithm) {
    if (algorithm_ != newAlgorithm) {
        algorithm_ = newAlgorithm;
        createImplementation();
    }
}

void Encryption::setMasterPassword(const std::string& password) {
    if (masterPassword_ != password) {
        masterPassword_ = password;
        createImplementation();
    }
}

std::string Encryption::encrypt(const std::string& plaintext) {
    if (!implementation_) {
        throw EncryptionError("Encryption implementation not initialized");
    }
    return implementation_->encrypt(plaintext);
}

std::string Encryption::decrypt(const std::string& encrypted_text, EncryptionType* forcedAlgorithm) {
    if (!implementation_) {
        throw EncryptionError("Encryption implementation not initialized");
    }
    
    if (forcedAlgorithm && *forcedAlgorithm != algorithm_) {
        // Create a temporary implementation for decryption with the forced algorithm
        auto tempImpl = EncryptionFactory::createForMasterPassword(
            *forcedAlgorithm, 
            masterPassword_, 
            taps_, 
            initialState_);
        return tempImpl->decrypt(encrypted_text);
    }
    
    return implementation_->decrypt(encrypted_text);
}

std::string Encryption::encryptWithSalt(const std::string& plaintext) {
    if (!implementation_) {
        throw EncryptionError("Encryption implementation not initialized");
    }
    
    // For AES, the salt is handled internally
    // For LFSR, we'll add a random salt
    if (algorithm_ == EncryptionType::LFSR) {
        std::vector<unsigned char> salt(PBKDF2_SALT_SIZE);
        if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
            throw EncryptionError("Failed to generate random salt");
        }
        std::string salt_str(salt.begin(), salt.end());
        return implementation_->encrypt(salt_str + plaintext);
    }
    
    return implementation_->encrypt(plaintext);
}

std::string Encryption::decryptWithSalt(const std::string& encrypted_text) {
    if (!implementation_) {
        throw EncryptionError("Encryption implementation not initialized");
    }
    
    std::string decrypted = implementation_->decrypt(encrypted_text);
    
    // For LFSR, remove the salt if it was added
    if (algorithm_ == EncryptionType::LFSR && decrypted.length() > PBKDF2_SALT_SIZE) {
        return decrypted.substr(PBKDF2_SALT_SIZE);
    }
    
    return decrypted;
}

std::string Encryption::lfsrProcess(const std::string& input) {
    // Use a fresh state for each call - no state sharing between operations
    std::vector<int> local_state = initialState_;
    
    std::string output;
    output.reserve(input.size());
    
    for (char c : input) {
        char processed_char = 0;
        for (int i = 0; i < 8; i++) {
            int output_bit = local_state[0];
            
            int feedback_bit = 0;
            for (int tap : taps_) {
                if (tap < local_state.size()) {
                    feedback_bit ^= local_state[tap];
                }
            }
            
            local_state.pop_back();
            local_state.insert(local_state.begin(), feedback_bit);
            
            processed_char |= (output_bit << i);
        }
        processed_char ^= c;
        output.push_back(processed_char);
    }
    
    return output;
}

std::string Encryption::aesEncrypt(const std::string& plaintext, const std::string& key) {
    try {
        // Generate a random salt for this encryption
        auto salt = generateSalt();
        
        // Derive a proper key from the password using PBKDF2
        auto deriveKeyResult = deriveKey(key, salt);
        
        // Initialize context using RAII wrapper (automatically freed on scope exit)
        CipherContextRAII ctx;
        
        // Generate random IV
        unsigned char iv[AES_IV_SIZE];
        if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
            throw EncryptionError("Failed to generate random IV");
        }
        
        // Initialize encryption operation
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, 
                              deriveKeyResult.data(), iv) != 1) {
            throw EncryptionError("Failed to initialize AES encryption");
        }
        
        // Prepare output buffer (plaintext + block_size for padding)
        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len = 0, ciphertext_len = 0;
        
        // Encrypt data
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, 
                             reinterpret_cast<const unsigned char*>(plaintext.data()), 
                             plaintext.size()) != 1) {
            throw EncryptionError("Failed during AES encryption");
        }
        ciphertext_len = len;
        
        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
            throw EncryptionError("Failed to finalize AES encryption");
        }
        ciphertext_len += len;
        
        // Note: ctx is automatically freed by RAII destructor here
        
        // Combine salt, IV and ciphertext for result (salt + IV + ciphertext)
        std::string result;
        result.reserve(PBKDF2_SALT_SIZE + AES_IV_SIZE + ciphertext_len);
        result.append(reinterpret_cast<char*>(salt.data()), PBKDF2_SALT_SIZE);
        result.append(reinterpret_cast<char*>(iv), AES_IV_SIZE);
        result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
        
        return result;
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("AES encryption failed: " + std::string(e.what()));
    }
}

std::string Encryption::aesDecrypt(const std::string& ciphertext, const std::string& key) {
    try {
        // Ensure ciphertext is large enough to contain salt + IV
        if (ciphertext.size() <= PBKDF2_SALT_SIZE + AES_IV_SIZE) {
            throw EncryptionError("Ciphertext too short");
        }
        
        // Extract salt from the beginning of ciphertext
        std::array<unsigned char, PBKDF2_SALT_SIZE> salt;
        std::copy(ciphertext.begin(), ciphertext.begin() + PBKDF2_SALT_SIZE, salt.begin());
        
        // Derive key from password using extracted salt
        auto deriveKeyResult = deriveKey(key, salt);
        
        // Extract IV from ciphertext (after salt)
        const unsigned char* iv = reinterpret_cast<const unsigned char*>(ciphertext.data() + PBKDF2_SALT_SIZE);
        const unsigned char* encrypted_data = iv + AES_IV_SIZE;
        int encrypted_len = ciphertext.size() - PBKDF2_SALT_SIZE - AES_IV_SIZE;
        
        // Initialize context using RAII wrapper (automatically freed on scope exit)
        CipherContextRAII ctx;
        
        // Initialize decryption operation
        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, 
                              deriveKeyResult.data(), iv) != 1) {
            throw EncryptionError("Failed to initialize AES decryption");
        }
        
        // Prepare output buffer
        std::vector<unsigned char> plaintext(encrypted_len);
        int len = 0, plaintext_len = 0;
        
        // Decrypt data
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, 
                             encrypted_data, encrypted_len) != 1) {
            throw EncryptionError("Failed during AES decryption");
        }
        plaintext_len = len;
        
        // Finalize decryption
        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1) {
            throw EncryptionError("Failed to finalize AES decryption");
        }
        plaintext_len += len;
        
        // Note: ctx is automatically freed by RAII destructor here
        
        return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("AES decryption failed: " + std::string(e.what()));
    }
}

std::array<unsigned char, PBKDF2_SALT_SIZE> Encryption::generateSalt() {
    std::array<unsigned char, PBKDF2_SALT_SIZE> salt;
    
    if (RAND_bytes(salt.data(), PBKDF2_SALT_SIZE) != 1) {
        throw EncryptionError("Failed to generate cryptographically secure salt");
    }
    
    return salt;
}

std::array<unsigned char, AES_KEY_SIZE> Encryption::deriveKey(const std::string& password, const std::array<unsigned char, PBKDF2_SALT_SIZE>& salt) {
    std::array<unsigned char, AES_KEY_SIZE> key;
    
    // Use PBKDF2 with SHA-256 for proper key derivation
    if (PKCS5_PBKDF2_HMAC(
        password.c_str(),           // Password
        password.length(),          // Password length
        salt.data(),               // Salt
        PBKDF2_SALT_SIZE,          // Salt length
        PBKDF2_ITERATIONS,         // Iteration count
        EVP_sha256(),              // Hash function (SHA-256)
        AES_KEY_SIZE,              // Key length
        key.data()                 // Output key
    ) != 1) {
        throw EncryptionError("PBKDF2 key derivation failed");
    }
    
    return key;
}

std::string Encryption::decryptMasterPassword(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& initState, const std::string& encrypted, const std::string& masterPassword) {
    Encryption enc(type, taps, initState, masterPassword);
    if (type == EncryptionType::LFSR) {
        return enc.decryptWithSalt(encrypted);
    } else if (type == EncryptionType::AES) {
        return enc.decrypt(encrypted);
    }
    throw std::runtime_error("Unknown encryption type for master password decryption");
}

std::string Encryption::encryptMasterPassword(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& initState, const std::string& masterPassword) {
    Encryption enc(type, taps, initState, masterPassword);
    if (type == EncryptionType::LFSR) {
        return enc.encryptWithSalt(masterPassword);
    } else if (type == EncryptionType::AES) {
        return enc.encrypt(masterPassword);
    }
    throw std::runtime_error("Unknown encryption type for master password encryption");
}
