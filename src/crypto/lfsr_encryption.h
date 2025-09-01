#ifndef LFSR_ENCRYPTION_H
#define LFSR_ENCRYPTION_H

#include <mutex>
#include <random>

#include "encryption_interface.h"

class LFSREncryption : public ISaltedEncryption {
   public:
    LFSREncryption(const std::vector<int>& taps, const std::vector<int>& initialState, const std::string& salt = "");

    // Implement IEncryption interface
    void setMasterPassword(const std::string& password) override;
    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& ciphertext) override;
    [[nodiscard]] EncryptionType getType() const override {
        return EncryptionType::LFSR;
    }

    // Implement ISaltedEncryption interface
    std::vector<std::string> encryptWithSalt(const std::vector<std::string>& plaintexts) override;
    std::vector<std::string> decryptWithSalt(const std::vector<std::string>& ciphertexts) override;

    // Additional methods
    void resetState();
    void updateSalt(const std::string& newSalt);
    std::string process(const std::string& input);
    std::string generateRandomSalt(size_t length = 16);

   private:
    std::vector<int> taps_;
    std::vector<int> initialState_;   // State after salt+password applied
    std::vector<int> originalState_;  // Truly original state - never modified
    std::vector<int> state_;          // Current working state
    std::string salt_;
    std::string masterPassword_;
    std::mt19937 rng_;
    std::mutex stateMutex_;

    void applySaltToState(const std::string& salt);
    int getNextBit();
};

#endif  // LFSR_ENCRYPTION_H