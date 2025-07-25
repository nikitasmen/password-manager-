#include "lfsr_encryption.h"
#include <stdexcept>
#include <algorithm>
#include <chrono>

LFSREncryption::LFSREncryption(const std::vector<int>& taps, const std::vector<int>& initialState)
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

std::string LFSREncryption::encrypt(const std::string& plaintext) {
    resetState();
    return process(plaintext);
}

std::string LFSREncryption::decrypt(const std::string& ciphertext) {
    // For LFSR, decryption is the same as encryption
    return encrypt(ciphertext);
}
