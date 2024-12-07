#include "GlobalConfig.h"
#include "Encryption.h"
#include <stdexcept>

Encryption::Encryption(const std::vector<int>& taps, const std::vector<int>& init_state) {
    if (init_state.size() < taps.back() + 1) {
        throw std::invalid_argument("Initial state size is too small for the specified taps.");
    }
    this->taps = taps;
    this->state = init_state;
}

std::string Encryption::encrypt(const std::string& plaintext) {
    std::string encrypted;
    for (char c : plaintext) {
        int keystream_bit = state[0]; // Output the first bit of the LFSR state
        char encrypted_char = c ^ keystream_bit; // XOR the character with the keystream bit
        encrypted.push_back(encrypted_char);

        // Calculate feedback bit using the specified taps
        int feedback_bit = 0;
        for (int tap : taps) {
            feedback_bit ^= state[tap];
        }

        state.pop_back();
        state.insert(state.begin(), feedback_bit); // Shift the LFSR state left and insert feedback bit
    }
    return encrypted;
}

std::string Encryption::decrypt(const std::string& encrypted_text) {
    return encrypt(encrypted_text); // XOR encryption is symmetric
}
