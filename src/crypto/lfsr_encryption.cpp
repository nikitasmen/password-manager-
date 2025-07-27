#include "lfsr_encryption.h"
#include <stdexcept>
#include <algorithm>
#include <chrono>
#include <numeric>
#include <random>
#include <sstream>
#include <iomanip>
#include <openssl/rand.h>

LFSREncryption::LFSREncryption(const std::vector<int>& taps, const std::vector<int>& initialState, const std::string& salt)
    : taps_(taps), initialState_(initialState), state_(initialState) {
    if (initialState.empty()) {
        throw EncryptionError("Initial state cannot be empty for LFSR encryption");
    }
    
    if (!taps.empty() && *std::max_element(taps.begin(), taps.end()) >= initialState.size()) {
        throw EncryptionError("Tap positions exceed initial state size");
    }
    
    // Initialize random number generator
    auto seed = std::chrono::system_clock::now().time_since_epoch().count();
    rng_.seed(static_cast<unsigned int>(seed));
    
    // Apply salt to the initial state if provided
    if (!salt.empty()) {
        salt_ = salt;
    }
}

void LFSREncryption::setMasterPassword(const std::string& password) {
    this->masterPassword_ = password;
    // Use the password and salt to modify the initial state
    if (!salt_.empty()) {
        applySaltToState(salt_);
    }
    if (!password.empty()) {
        applySaltToState(password);
    }
}

void LFSREncryption::applySaltToState(const std::string& salt) {
    if (salt.empty() || initialState_.empty()) {
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
    
    // Update the initial state to match the newly modified state
    initialState_ = state_;
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
    unsigned char saltBytes[16];
    if (RAND_bytes(saltBytes, sizeof(saltBytes)) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }
    std::string salt(reinterpret_cast<const char*>(saltBytes), sizeof(saltBytes));

    std::vector<std::string> ciphertexts;
    for (const auto& plaintext : plaintexts) {
        LFSREncryption encryptor(taps_, initialState_, salt);
        encryptor.setMasterPassword(masterPassword_);
        ciphertexts.push_back(salt + encryptor.process(plaintext));
    }
    return ciphertexts;
}

std::vector<std::string> LFSREncryption::decryptWithSalt(const std::vector<std::string>& ciphertexts) {
    if (ciphertexts.empty()) {
        return {};
    }

    std::string salt = ciphertexts[0].substr(0, 16);

    std::vector<std::string> plaintexts;
    for (const auto& ciphertext : ciphertexts) {
        if (ciphertext.length() < 16) {
            throw std::runtime_error("Invalid ciphertext for salted LFSR decryption");
        }
        std::string actualCiphertext = ciphertext.substr(16);
        LFSREncryption decryptor(taps_, initialState_, salt);
        decryptor.setMasterPassword(masterPassword_);
        plaintexts.push_back(decryptor.process(actualCiphertext));
    }
    return plaintexts;
}

std::string LFSREncryption::encrypt(const std::string& plaintext) {
    return process(plaintext);
}

std::string LFSREncryption::decrypt(const std::string& ciphertext) {
    return process(ciphertext);
}
