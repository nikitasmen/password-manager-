#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <stdexcept>

// Exception class for encryption errors
class EncryptionError : public std::runtime_error {
public:
    explicit EncryptionError(const std::string& message) 
        : std::runtime_error("Encryption Error: " + message) {}
};

/**
 * @class Encryption
 * @brief Provides encryption and decryption functionality using LFSR-based stream cipher
 * 
 * This class implements a simple encryption mechanism using a Linear Feedback Shift Register (LFSR)
 * It can be used to encrypt/decrypt sensitive information like passwords
 */
class Encryption {
private:
    std::vector<int> taps;          // Feedback taps for the LFSR
    std::vector<int> state;         // Current state of the LFSR
    std::vector<int> initial_state; // Saved initial state for reset operations
    std::mt19937 rng;               // Mersenne Twister random number generator
    
    // Update the LFSR state and return the output bit
    int getNextBit();
    
    // Reset the LFSR to its initial state for a new encryption/decryption
    void resetState();
    
    // Helper function to generate a random salt string
    std::string generateSalt(size_t length = 8);

public:
    /**
     * @brief Construct a new Encryption object
     * 
     * @param taps The feedback taps for the LFSR
     * @param init_state The initial state of the LFSR
     */
    Encryption(const std::vector<int>& taps, const std::vector<int>& init_state);
    
    /**
     * @brief Encrypt a plaintext string
     * 
     * @param plaintext The text to encrypt
     * @return std::string The encrypted text
     */
    std::string encrypt(const std::string& plaintext);
    
    /**
     * @brief Decrypt an encrypted string
     * 
     * @param encrypted_text The text to decrypt
     * @return std::string The decrypted plaintext
     */
    std::string decrypt(const std::string& encrypted_text);
    
    /**
     * @brief Encrypt plaintext with added salt for improved security
     * 
     * @param plaintext The text to encrypt
     * @return std::string The encrypted text with embedded salt
     */
    std::string encryptWithSalt(const std::string& plaintext);
    
    /**
     * @brief Decrypt text that was encrypted with salt
     * 
     * @param encrypted_text The text to decrypt
     * @return std::string The decrypted plaintext with salt removed
     */
    std::string decryptWithSalt(const std::string& encrypted_text);
};

#endif // ENCRYPTION_H
