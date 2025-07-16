#include "./encryption.h"
#include <stdexcept>
#include <algorithm>
#include <iostream>

Encryption::Encryption(const std::vector<int>& taps, const std::vector<int>& init_state) {
    if (init_state.empty()) {
        throw EncryptionError("Initial state cannot be empty");
    }
    
    if (!taps.empty() && taps.back() >= init_state.size()) {
        throw EncryptionError("Initial state size is too small for the specified taps");
    }
    
    // Initialize the encryption parameters
    this->taps = taps;
    this->initial_state.assign(init_state.begin(), init_state.end());
    this->state.assign(init_state.begin(), init_state.end());
    
    // Seed the random number generator with current time
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    rng = std::mt19937(seed);
}

int Encryption::getNextBit() {
    try {
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
    // Reset to the saved initial state
    this->state.clear();
    this->state.assign(initial_state.begin(), initial_state.end());
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
        std::string encrypted;
        encrypted.reserve(plaintext.size()); // Pre-allocate memory
        
        for (char c : plaintext) {
            // For each character, generate 8 bits from the LFSR
            char encrypted_char = 0;
            for (int i = 0; i < 8; i++) {
                int bit = getNextBit();
                encrypted_char |= (bit << i); // Build up the byte
            }
            
            // XOR with the plaintext character
            encrypted_char ^= c;
            encrypted.push_back(encrypted_char);
        }
        
        return encrypted;
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("Encryption failed: " + std::string(e.what()));
    }
}

std::string Encryption::decrypt(const std::string& encrypted_text) {
    try {
        std::string decrypted;
        decrypted.reserve(encrypted_text.size()); // Pre-allocate memory
        
        for (char c : encrypted_text) {
            // For each character, generate 8 bits from the LFSR
            char decrypted_char = 0;
            for (int i = 0; i < 8; i++) {
                int bit = getNextBit();
                decrypted_char |= (bit << i); // Build up the byte
            }
            
            // XOR with the encrypted character
            decrypted_char ^= c;
            decrypted.push_back(decrypted_char);
        }
        
        return decrypted;
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
        
        // Reset state to initial state that was provided during construction
        resetState();
        
        // Encrypt the plaintext
        std::string encrypted = encrypt(plaintext);
        
        // Return salt + encrypted data
        std::string result = salt + encrypted;
        return result;
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
        
        // Extract salt (first 8 characters) - we don't actually use it for decryption now
        std::string salt = encrypted_text.substr(0, 8);
        
        // Reset state to initial state that was provided during construction
        resetState();
        
        // Extract and decrypt the rest
        std::string encryptedData = encrypted_text.substr(8);
        std::string plaintext = decrypt(encryptedData);
        
        return plaintext;
    } catch (const EncryptionError& e) {
        throw; // Re-throw encryption-specific errors
    } catch (const std::exception& e) {
        throw EncryptionError("Salt-based decryption failed: " + std::string(e.what()));
    }
}
