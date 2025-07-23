#include "lfsr_encryption.h"
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <openssl/rand.h> // Added for RAND_bytes
#include <stdexcept>
#include <chrono>

// Implement getNextBit, resetState, lfsrProcess from original

LfsrEncryption::LfsrEncryption(const std::vector<int>& taps, const std::vector<int>& init_state, const std::string& password) {
    if (init_state.empty()) {
        throw EncryptionError("Initial state cannot be empty for LFSR-based encryption");
    }
    if (!taps.empty() && taps.back() >= init_state.size()) {
        throw EncryptionError("Initial state size is too small for the specified taps");
    }
    this->taps = taps;
    this->initial_state = init_state;
    this->state = init_state;
    this->masterPassword = password;
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    rng = std::mt19937(seed);
    if (!password.empty()) {
        std::string hash = computeSha256(password);
        for (size_t i = 0; i < initial_state.size() && i < hash.size(); ++i) {
            initial_state[i] ^= (hash[i] & 1);
        }
        state = initial_state;
    }
}

int LfsrEncryption::getNextBit() {
    std::lock_guard<std::mutex> lock(state_mutex);
    int output_bit = state[0];
    int feedback_bit = 0;
    for (int tap : taps) {
        if (tap < state.size()) {
            feedback_bit ^= state[tap];
        } else {
            throw EncryptionError("Tap index out of range");
        }
    }
    state.pop_back();
    state.insert(state.begin(), feedback_bit);
    return output_bit;
}

void LfsrEncryption::resetState() {
    std::lock_guard<std::mutex> lock(state_mutex);
    state = initial_state;
}

std::string LfsrEncryption::lfsrProcess(const std::string& input) {
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

std::string LfsrEncryption::computeSha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::string LfsrEncryption::encrypt(const std::string& plaintext) {
    return lfsrProcess(plaintext);
}

std::string LfsrEncryption::decrypt(const std::string& encrypted_text) {
    return lfsrProcess(encrypted_text);
}

std::string LfsrEncryption::encryptWithSalt(const std::string& plaintext) {
    auto salt = generateSalt(); // Need to implement generateSalt or use from somewhere
    std::string saltStr(reinterpret_cast<const char*>(salt.data()), PBKDF2_SALT_SIZE); // Assume PBKDF2_SALT_SIZE=16
    return lfsrProcess(saltStr + plaintext);
}

std::string LfsrEncryption::decryptWithSalt(const std::string& encrypted_text) {
    if (encrypted_text.size() <= PBKDF2_SALT_SIZE) { // PBKDF2_SALT_SIZE
        throw EncryptionError("Encrypted text too short to contain salt");
    }
    std::string saltedData = lfsrProcess(encrypted_text);
    return saltedData.substr(PBKDF2_SALT_SIZE);
}

void LfsrEncryption::setMasterPassword(const std::string& password) {
    masterPassword = password;
    // Update state with new password
    if (!password.empty()) {
        std::string hash = computeSha256(password);
        for (size_t i = 0; i < initial_state.size() && i < hash.size() / 2; ++i) {
            initial_state[i] ^= (static_cast<int>(hash[i * 2]) % 2);
        }
        state = initial_state;
    }
}

std::string LfsrEncryption::hash(const std::string& input) {
    return computeSha256(input);
}

std::array<unsigned char, 16> LfsrEncryption::generateSalt() {
    std::array<unsigned char, 16> salt;
    if (RAND_bytes(salt.data(), 16) != 1) {
        throw EncryptionError("Failed to generate salt");
    }
    return salt;
} 