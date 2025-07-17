#include "./encryption.h"
#include <stdexcept>
#include <algorithm>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>

Encryption::Encryption(EncryptionType algorithm, const std::vector<int>& taps, const std::vector<int>& init_state, const std::string& password) {
    if (init_state.empty()) {
        throw EncryptionError("Initial state cannot be empty");
    }
    
    if (!taps.empty() && taps.back() >= init_state.size()) {
        throw EncryptionError("Initial state size is too small for the specified taps");
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

std::string Encryption::generateSalt(size_t length) {
    static const char charset[] = 
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    
    std::string salt;
    salt.reserve(length);
    
    for (size_t i = 0; i < length; ++i) {
        salt.push_back(charset[rng() % (sizeof(charset) - 1)]);
    }
    
    return salt;
}

std::string Encryption::encrypt(const std::string& plaintext) {
    try {
        // Choose encryption algorithm based on current setting
        if (algorithm == EncryptionType::AES) {
            // For simplicity, using an empty key for this example - real implementation would use a password
            std::string key = "default_password"; // This should be properly implemented
            return aesEncrypt(plaintext, key);
        }
        else { // LFSR algorithm
            // Create a local copy of the state
            std::vector<int> local_state;
            
            {
                // Lock only while copying the state
                std::lock_guard<std::mutex> lock(state_mutex);
                local_state = initial_state;
            }
            
            std::string encrypted;
            encrypted.reserve(plaintext.size()); // Pre-allocate memory
            
            for (char c : plaintext) {
                // For each character, generate 8 bits from the LFSR
                char encrypted_char = 0;
                for (int i = 0; i < 8; i++) {
                    // Get the output bit from local state
                    int output_bit = local_state[0];
                    
                    // Calculate feedback bit using the specified taps
                    int feedback_bit = 0;
                    for (int tap : taps) {
                        if (tap < local_state.size()) {
                            feedback_bit ^= local_state[tap];
                        }
                    }
                    
                    // Update the local state
                    local_state.pop_back();
                    local_state.insert(local_state.begin(), feedback_bit);
                    
                    encrypted_char |= (output_bit << i); // Build up the byte
                }
                
                // XOR with the plaintext character
                encrypted_char ^= c;
                encrypted.push_back(encrypted_char);
            }
            
            return encrypted;
        }
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("Encryption failed: " + std::string(e.what()));
    }
}

std::string Encryption::decrypt(const std::string& encrypted_text, std::optional<EncryptionType> forcedAlgorithm) {
    try {
        // Use the specified algorithm or default to the current one
        EncryptionType actualAlgorithm = forcedAlgorithm.value_or(algorithm);
        
        // Choose decryption algorithm
        if (actualAlgorithm == EncryptionType::AES) {
            // For AES, we need to extract the IV from the beginning of the encrypted text
            // First 16 bytes are the IV
            if (encrypted_text.size() <= AES_IV_SIZE) {
                throw EncryptionError("Encrypted data too short for AES");
            }
            
            // For simplicity, using an empty key for this example - real implementation would use a password
            std::string key = "default_password"; // This should be properly implemented
            return aesDecrypt(encrypted_text, key);
        } 
        else { // LFSR algorithm
            // Create a local copy of the state
            std::vector<int> local_state;
            
            {
                // Lock only while copying the state
                std::lock_guard<std::mutex> lock(state_mutex);
                local_state = initial_state;
            }
            
            std::string decrypted;
            decrypted.reserve(encrypted_text.size()); // Pre-allocate memory
            
            for (char c : encrypted_text) {
                // For each character, generate 8 bits from the LFSR
                char decrypted_char = 0;
                for (int i = 0; i < 8; i++) {
                    // Get the output bit from local state
                    int output_bit = local_state[0];
                    
                    // Calculate feedback bit using the specified taps
                    int feedback_bit = 0;
                    for (int tap : taps) {
                        if (tap < local_state.size()) {
                            feedback_bit ^= local_state[tap];
                        }
                    }
                    
                    // Update the local state
                    local_state.pop_back();
                    local_state.insert(local_state.begin(), feedback_bit);
                    
                    decrypted_char |= (output_bit << i); // Build up the byte
                }
                
                // XOR with the encrypted character
                decrypted_char ^= c;
                decrypted.push_back(decrypted_char);
            }
            
            return decrypted;
        }
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("Decryption failed: " + std::string(e.what()));
    }
}

std::string Encryption::encryptWithSalt(const std::string& plaintext) {
    try {
        // Generate a random salt
        std::string salt = generateSalt(8);
        
        if (algorithm == EncryptionType::AES) {
            // For AES, use the master password for encryption
            std::string encryptedData = aesEncrypt(plaintext, masterPassword);
            return salt + encryptedData;
        }
        else { // LFSR algorithm
            // Use a fresh encryption for each call - no state sharing between operations
            std::vector<int> local_state = initial_state;
            
            std::string encrypted;
            encrypted.reserve(plaintext.size());
            
            for (char c : plaintext) {
                char encrypted_char = 0;
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
                    
                    encrypted_char |= (output_bit << i);
                }
                encrypted_char ^= c;
                encrypted.push_back(encrypted_char);
            }
            
            // Return salt + encrypted data
            return salt + encrypted;
        }
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("Salt-based encryption failed: " + std::string(e.what()));
    }
}

std::string Encryption::decryptWithSalt(const std::string& encrypted_text) {
    try {
        // Check if encrypted text is long enough to contain salt
        if (encrypted_text.size() <= 8) {
            throw EncryptionError("Encrypted text too short to contain salt");
        }
        
        // Extract salt (first 8 characters) - we don't actually use it for decryption
        std::string salt = encrypted_text.substr(0, 8);
        std::string encryptedData = encrypted_text.substr(8);
        
        if (algorithm == EncryptionType::AES) {
            // For AES, use the master password to decrypt
            return aesDecrypt(encryptedData, masterPassword);
        }
        else { // LFSR algorithm
            // Use a fresh decryption for each call - no state sharing between operations
            std::vector<int> local_state = initial_state;
            
            std::string plaintext;
            plaintext.reserve(encryptedData.size());
            
            for (char c : encryptedData) {
                char decrypted_char = 0;
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
                    
                    decrypted_char |= (output_bit << i);
                }
                decrypted_char ^= c;
                plaintext.push_back(decrypted_char);
            }
            
            return plaintext;
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

std::string Encryption::aesEncrypt(const std::string& plaintext, const std::string& key) {
    try {
        // Derive a proper key from the password
        auto deriveKeyResult = deriveKey(key);
        
        // Initialize context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw EncryptionError("Failed to create OpenSSL cipher context");
        }
        
        // Generate random IV
        unsigned char iv[AES_IV_SIZE];
        if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw EncryptionError("Failed to generate random IV");
        }
        
        // Initialize encryption operation
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                              deriveKeyResult.data(), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw EncryptionError("Failed to initialize AES encryption");
        }
        
        // Prepare output buffer (plaintext + block_size for padding)
        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len = 0, ciphertext_len = 0;
        
        // Encrypt data
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                             reinterpret_cast<const unsigned char*>(plaintext.data()), 
                             plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw EncryptionError("Failed during AES encryption");
        }
        ciphertext_len = len;
        
        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw EncryptionError("Failed to finalize AES encryption");
        }
        ciphertext_len += len;
        
        // Cleanup
        EVP_CIPHER_CTX_free(ctx);
        
        // Combine IV and ciphertext for result
        std::string result;
        result.reserve(AES_IV_SIZE + ciphertext_len);
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
        // Ensure ciphertext is large enough to contain IV
        if (ciphertext.size() <= AES_IV_SIZE) {
            throw EncryptionError("Ciphertext too short");
        }
        
        // Derive key from password
        auto deriveKeyResult = deriveKey(key);
        
        // Extract IV from ciphertext
        const unsigned char* iv = reinterpret_cast<const unsigned char*>(ciphertext.data());
        const unsigned char* encrypted_data = iv + AES_IV_SIZE;
        int encrypted_len = ciphertext.size() - AES_IV_SIZE;
        
        // Initialize context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw EncryptionError("Failed to create OpenSSL cipher context");
        }
        
        // Initialize decryption operation
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                              deriveKeyResult.data(), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw EncryptionError("Failed to initialize AES decryption");
        }
        
        // Prepare output buffer
        std::vector<unsigned char> plaintext(encrypted_len);
        int len = 0, plaintext_len = 0;
        
        // Decrypt data
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                             encrypted_data, encrypted_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw EncryptionError("Failed during AES decryption");
        }
        plaintext_len = len;
        
        // Finalize decryption
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw EncryptionError("Failed to finalize AES decryption");
        }
        plaintext_len += len;
        
        // Cleanup
        EVP_CIPHER_CTX_free(ctx);
        
        return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("AES decryption failed: " + std::string(e.what()));
    }
}

std::array<unsigned char, AES_KEY_SIZE> Encryption::deriveKey(const std::string& password) {
    std::array<unsigned char, AES_KEY_SIZE> key;
    
    // In a real implementation, you would use a proper KDF like PBKDF2, Argon2, etc.
    // For this example, we'll use a simple approach (not recommended for production)
    
    // Fill with zeros first
    std::fill(key.begin(), key.end(), 0);
    
    // Copy password bytes or hash them into the key
    size_t copy_len = std::min(password.size(), key.size());
    std::copy(password.begin(), password.begin() + copy_len, key.begin());
    
    return key;
}
