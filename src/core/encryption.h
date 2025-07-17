#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <stdexcept>
#include <mutex>
#include <array>
#include <optional>
#include "../config/GlobalConfig.h"

// Exception class for encryption errors
class EncryptionError : public std::runtime_error {
public:
    explicit EncryptionError(const std::string& message) 
        : std::runtime_error("Encryption Error: " + message) {}
};

// Constants for AES implementation
constexpr size_t AES_BLOCK_SIZE = 16;  // AES uses 128-bit (16-byte) blocks
constexpr size_t AES_KEY_SIZE = 32;    // Using AES-256 (32-byte key)
constexpr size_t AES_IV_SIZE = 16;     // Initialization vector size

// Constants for PBKDF2 key derivation
constexpr size_t PBKDF2_SALT_SIZE = 16;    // 128-bit salt (sufficient for security)
constexpr int PBKDF2_ITERATIONS = 100000;  // Number of PBKDF2 iterations (NIST recommended minimum)

/**
 * @class Encryption
 * @brief Provides encryption and decryption functionality with multiple algorithms
 * 
 * This class implements multiple encryption mechanisms:
 * 1. LFSR-based stream cipher (original implementation)
 * 2. AES-256 for stronger encryption
 */
class Encryption {
private:
    EncryptionType algorithm;       // The encryption algorithm to use
    std::vector<int> taps;          // Feedback taps for the LFSR
    std::vector<int> state;         // Current state of the LFSR
    std::vector<int> initial_state; // Saved initial state for reset operations
    std::mt19937 rng;               // Mersenne Twister random number generator
    std::string masterPassword;     // Master password for AES encryption
    
    // LFSR methods
    int getNextBit();
    void resetState();
    std::string lfsrProcess(const std::string& input); // Helper for LFSR encryption/decryption
    
    // AES methods
    std::string aesEncrypt(const std::string& plaintext, const std::string& key);
    std::string aesDecrypt(const std::string& ciphertext, const std::string& key);
    std::array<unsigned char, AES_KEY_SIZE> deriveKey(const std::string& password, const std::array<unsigned char, PBKDF2_SALT_SIZE>& salt);
    std::array<unsigned char, PBKDF2_SALT_SIZE> generateSalt();
    
    // Mutex for thread safety
    mutable std::mutex state_mutex;

public:
    /**
     * @brief Construct a new Encryption object
     * 
     * @param algorithm The encryption algorithm to use
     * @param taps The feedback taps for the LFSR (for LFSR algorithm)
     * @param init_state The initial state of the LFSR (for LFSR algorithm)
     * @param password The master password for AES encryption (optional for LFSR)
     */
    Encryption(EncryptionType algorithm, const std::vector<int>& taps, const std::vector<int>& init_state, const std::string& password = "");
    
    /**
     * @brief Get current encryption algorithm
     * 
     * @return EncryptionType The current algorithm
     */
    EncryptionType getAlgorithm() const { return algorithm; }
    
    /**
     * @brief Set encryption algorithm
     * 
     * @param newAlgorithm The algorithm to use
     */
    void setAlgorithm(EncryptionType newAlgorithm);
    
    /**
     * @brief Set the master password for AES encryption
     * 
     * @param password The master password
     */
    void setMasterPassword(const std::string& password);
    
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
     * @param forcedAlgorithm Force a specific algorithm (useful for legacy data)
     * @return std::string The decrypted plaintext
     */
    std::string decrypt(const std::string& encrypted_text, EncryptionType* forcedAlgorithm = nullptr);
    
    /**
     * @brief Encrypt plaintext with added salt for improved security
     * 
     * @param plaintext The text to encrypt
     * @return std::string The encrypted text with embedded salt and algorithm identifier
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
