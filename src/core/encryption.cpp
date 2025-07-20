#include "./encryption.h"
#include <stdexcept>
#include <algorithm>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

// Implementation of CipherContextRAII
CipherContextRAII::CipherContextRAII() : ctx_(EVP_CIPHER_CTX_new()) {
    if (!ctx_) {
        throw EncryptionError("Failed to create OpenSSL cipher context");
    }
}

CipherContextRAII::~CipherContextRAII() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
    }
}

CipherContextRAII::CipherContextRAII(CipherContextRAII&& other) noexcept : ctx_(other.ctx_) {
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

Encryption::Encryption(EncryptionType algorithm, const std::vector<int>& taps, const std::vector<int>& init_state, const std::string& password) {
    // Only check init_state and taps for LFSR-based encryption types
    if (algorithm == EncryptionType::LFSR || algorithm == EncryptionType::AES_LFSR) {
        if (init_state.empty()) {
            throw EncryptionError("Initial state cannot be empty for LFSR-based encryption");
        }
        
        if (!taps.empty() && taps.back() >= init_state.size()) {
            throw EncryptionError("Initial state size is too small for the specified taps");
        }
    }
    
    // Lock to ensure thread safety during initialization
    std::lock_guard<std::mutex> lock(state_mutex);
    
    // Initialize the encryption parameters
    this->algorithm = algorithm;
    this->taps = taps;
    this->initial_state.assign(init_state.begin(), init_state.end());
    this->state.assign(init_state.begin(), init_state.end());
    this->masterPassword = password;
    
    // Seed the random number generator with current time
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    rng = std::mt19937(seed);
}

int Encryption::getNextBit() {
    try {
        // Lock to ensure thread safety during state modification
        std::lock_guard<std::mutex> lock(state_mutex);
        
        // Get the output bit
        int output_bit = state[0];
        
        // Calculate feedback bit using the specified taps
        int feedback_bit = 0;
        for (int tap : taps) {
            if (tap < state.size()) {
                feedback_bit ^= state[tap];
            } else {
                throw EncryptionError("Tap index out of range");
            }
        }
        
        // Shift the register and insert the feedback bit
        state.pop_back();
        state.insert(state.begin(), feedback_bit);
        
        return output_bit;
    } catch (const std::out_of_range& e) {
        throw EncryptionError("State access error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        throw EncryptionError("Bit generation error: " + std::string(e.what()));
    }
}

void Encryption::resetState() {
    // Lock to ensure thread safety during state reset
    std::lock_guard<std::mutex> lock(state_mutex);
    
    // Reset to the saved initial state
    this->state = initial_state; // Using assignment instead of clear+assign
}

std::string Encryption::encrypt(const std::string& plaintext) {
    try {
        // Choose encryption algorithm based on current setting
        if (algorithm == EncryptionType::AES) {
            // Use the master password for AES encryption
            return aesEncrypt(plaintext, masterPassword);
        }
        else if (algorithm == EncryptionType::AES_LFSR) {
            // Dual encryption: AES first, then LFSR
            // Step 1: Encrypt with AES using master password
            std::string aesEncrypted = aesEncrypt(plaintext, masterPassword);
            
            // Step 2: Encrypt the AES result with LFSR
            std::string dualEncrypted = lfsrProcess(aesEncrypted);
            
            return dualEncrypted;
        }
        else { // LFSR algorithm
            return lfsrProcess(plaintext);
        }
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("Encryption failed: " + std::string(e.what()));
    }
}

std::string Encryption::decrypt(const std::string& encrypted_text, EncryptionType* forcedAlgorithm) {
    try {
        // Use the specified algorithm or default to the current one
        EncryptionType actualAlgorithm = forcedAlgorithm ? *forcedAlgorithm : algorithm;
        
        // Choose decryption algorithm
        if (actualAlgorithm == EncryptionType::AES) {
            // For AES, we need to extract the IV from the beginning of the encrypted text
            // First 16 bytes are the IV
            if (encrypted_text.size() <= AES_IV_SIZE) {
                throw EncryptionError("Encrypted data too short for AES");
            }
            
            // Use the master password for AES decryption
            return aesDecrypt(encrypted_text, masterPassword);
        }
        else if (actualAlgorithm == EncryptionType::AES_LFSR) {
            // Dual decryption: LFSR first, then AES
            // Step 1: Decrypt LFSR layer
            std::string lfsrDecrypted = lfsrProcess(encrypted_text);
            
            // Step 2: Decrypt AES layer using master password
            std::string finalDecrypted = aesDecrypt(lfsrDecrypted, masterPassword);
            
            return finalDecrypted;
        }
        else { // LFSR algorithm
            return lfsrProcess(encrypted_text);
        }
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("Decryption failed: " + std::string(e.what()));
    }
}

std::string Encryption::encryptWithSalt(const std::string& plaintext) {
    try {
        if (algorithm == EncryptionType::AES) {
            // For AES, use the master password for encryption (salt is handled internally)
            return aesEncrypt(plaintext, masterPassword);
        }
        else { // LFSR algorithm
            // Generate a simple 8-byte salt for LFSR
            std::string salt;
            salt.resize(8);
            if (RAND_bytes(reinterpret_cast<unsigned char*>(&salt[0]), 8) != 1) {
                throw EncryptionError("Failed to generate salt for LFSR");
            }
            
            // Return salt + encrypted data
            return salt + lfsrProcess(plaintext);
        }
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("Salt-based encryption failed: " + std::string(e.what()));
    }
}

std::string Encryption::decryptWithSalt(const std::string& encrypted_text) {
    try {
        if (algorithm == EncryptionType::AES) {
            // For AES, the salt and IV are embedded in the encrypted data
            // Pass the full encrypted_text to aesDecrypt
            return aesDecrypt(encrypted_text, masterPassword);
        }
        else if (algorithm == EncryptionType::AES_LFSR) {
            return decrypt(encrypted_text);
        }
        else { // LFSR algorithm
            // Check if encrypted text is long enough to contain salt
            if (encrypted_text.size() <= 8) {
                throw EncryptionError("Encrypted text too short to contain salt");
            }
            
            // Extract salt (first 8 characters) and encrypted data for LFSR
            std::string encryptedData = encrypted_text.substr(8);
            return lfsrProcess(encryptedData);
        }
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("Salt-based decryption failed: " + std::string(e.what()));
    }
}

void Encryption::setAlgorithm(EncryptionType newAlgorithm) {
    std::lock_guard<std::mutex> lock(state_mutex);
    algorithm = newAlgorithm;
}

void Encryption::setMasterPassword(const std::string& password) {
    std::lock_guard<std::mutex> lock(state_mutex);
    masterPassword = password;
}

std::string Encryption::lfsrProcess(const std::string& input) {
    // Use a fresh state for each call - no state sharing between operations
    std::vector<int> local_state = initial_state;
    
    std::string output;
    output.reserve(input.size());
    
    for (char c : input) {
        char processed_char = 0;
        for (int i = 0; i < 8; i++) {
            int output_bit = local_state[0];
            
            int feedback_bit = 0;
            for (int tap : taps) {
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
