#include "lfsr_encryption.h"
#include <algorithm>
#include <chrono>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <openssl/rand.h>

LFSREncryption::LFSREncryption(const std::vector<int>& taps, const std::vector<int>& initialState, const std::string& salt)
    : taps_(taps), initialState_(initialState), state_(initialState), originalState_(initialState) {
    if (initialState.empty()) {
        throw EncryptionError("Initial state cannot be empty for LFSR encryption");
    }
    
    if (!taps.empty() && *std::max_element(taps.begin(), taps.end()) >= initialState.size()) {
        throw EncryptionError("Tap positions exceed initial state size");
    }
    
    // Initialize random number generator
    auto seed = std::chrono::system_clock::now().time_since_epoch().count();
    rng_.seed(static_cast<unsigned int>(seed));
    
    // Apply salt to the state if provided
    if (!salt.empty()) {
        salt_ = salt;
        applySaltToState(salt_);
    }
}

void LFSREncryption::setMasterPassword(const std::string& password) {
    this->masterPassword_ = password;
    
    // Restore state to original initial state before applying any modifications
    state_ = originalState_;
    
    // Apply salt and password in a deterministic order
    if (!salt_.empty()) {
        applySaltToState(salt_);
    }
    if (!password.empty()) {
        applySaltToState(password);
    }
    
    // Save this as the new initial state (post-salt/password)
    initialState_ = state_;
}

void LFSREncryption::applySaltToState(const std::string& salt) {
    if (salt.empty() || state_.empty()) {
        return;
    }
    
    // XOR each bit of the state with the salt
    for (size_t i = 0; i < state_.size() && i < salt.size() * 8; ++i) {
        // Get the bit from the salt (cycling through salt bytes and bits)
        size_t byteIndex = (i / 8) % salt.size();
        int bit = (salt[byteIndex] >> (i % 8)) & 1;
        
        // XOR the state bit with the salt bit
        state_[i % state_.size()] ^= bit;
    }
    
    // We don't modify originalState_ - it stays untouched
}

int LFSREncryption::getNextBit() {
    if (taps_.empty()) {
        throw EncryptionError("No taps defined for LFSR");
    }
    
    int feedback = 0;
    for (int tap : taps_) {
        feedback ^= state_[tap];
    }
    
    int output = state_.back();
    state_.pop_back();
    state_.insert(state_.begin(), feedback);
    
    return output;
}

void LFSREncryption::resetState() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    // Reset to the salt+password modified state, not the original state
    state_ = initialState_;
}

std::string LFSREncryption::process(const std::string& input) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    std::string output;
    output.reserve(input.length());
    
    for (char c : input) {
        int key_byte = 0;
        for (int i = 0; i < 8; ++i) {
            key_byte = (key_byte << 1) | getNextBit();
        }
        output.push_back(static_cast<char>(c ^ key_byte));
    }
    
    return output;
}

std::string LFSREncryption::generateRandomSalt(size_t length) {
    static const std::string charset = 
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    
    std::string salt;
    salt.reserve(length);
    
    std::uniform_int_distribution<size_t> dist(0, charset.size() - 1);
    
    for (size_t i = 0; i < length; ++i) {
        salt += charset[dist(rng_)];
    }
    
    return salt;
}

std::vector<std::string> LFSREncryption::encryptWithSalt(const std::vector<std::string>& plaintexts) {
    if (plaintexts.empty()) {
        return {};
    }
    
    // Generate a single salt for all plaintexts in this batch
    unsigned char saltBytes[16];
    if (RAND_bytes(saltBytes, sizeof(saltBytes)) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }
    std::string salt(reinterpret_cast<const char*>(saltBytes), sizeof(saltBytes));

    // Create a single encryptor instance with the salt
    LFSREncryption encryptor(taps_, originalState_, salt);
    encryptor.setMasterPassword(masterPassword_);
    
    std::vector<std::string> ciphertexts;
    ciphertexts.reserve(plaintexts.size());
    
    for (const auto& plaintext : plaintexts) {
        // Reset state for each plaintext to ensure consistency
        encryptor.resetState();
        std::string encrypted = encryptor.process(plaintext);
        ciphertexts.push_back(salt + encrypted);
    }
    return ciphertexts;
}

std::vector<std::string> LFSREncryption::decryptWithSalt(const std::vector<std::string>& ciphertexts) {
    if (ciphertexts.empty()) {
        return {};
    }

    // Validate all ciphertexts have minimum length
    for (const auto& ciphertext : ciphertexts) {
        if (ciphertext.length() < 16) {
            throw std::runtime_error("Invalid ciphertext for salted LFSR decryption: too short");
        }
    }
    
    std::vector<std::string> plaintexts;
    plaintexts.reserve(ciphertexts.size());
    
    // Check if all ciphertexts share the same salt (new format)
    std::string firstSalt = ciphertexts[0].substr(0, 16);
    bool sharedSalt = true;
    
    for (const auto& ciphertext : ciphertexts) {
        if (ciphertext.substr(0, 16) != firstSalt) {
            sharedSalt = false;
            break;
        }
    }
    
    if (sharedSalt) {
        // New format: all ciphertexts share the same salt
        LFSREncryption decryptor(taps_, originalState_, firstSalt);
        decryptor.setMasterPassword(masterPassword_);
        
        for (const auto& ciphertext : ciphertexts) {
            std::string actualCiphertext = ciphertext.substr(16);
            // Reset state for each ciphertext to ensure consistency
            decryptor.resetState();
            plaintexts.push_back(decryptor.process(actualCiphertext));
        }
    } else {
        // Legacy format: each ciphertext has its own salt
        for (const auto& ciphertext : ciphertexts) {
            std::string salt = ciphertext.substr(0, 16);
            std::string actualCiphertext = ciphertext.substr(16);
            
            // Create a decryptor for this specific salt
            LFSREncryption decryptor(taps_, originalState_, salt);
            decryptor.setMasterPassword(masterPassword_);
            plaintexts.push_back(decryptor.process(actualCiphertext));
        }
    }
    
    return plaintexts;
}

std::string LFSREncryption::encrypt(const std::string& plaintext) {
    return process(plaintext);
}

std::string LFSREncryption::decrypt(const std::string& ciphertext) {
    return process(ciphertext);
}
