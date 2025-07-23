#ifndef LFSR_ENCRYPTION_H
#define LFSR_ENCRYPTION_H

#include "../core/encryption.h" 
#include <vector>
#include <string>
#include <mutex>
#include <random>
#include <array> // Added for generateSalt

class LfsrEncryption : public Encryption {
private:
    std::vector<int> taps;
    std::vector<int> state;
    std::vector<int> initial_state;
    std::mt19937 rng;
    mutable std::mutex state_mutex;
    std::string masterPassword; // To make keyed, use this
    std::array<unsigned char, PBKDF2_SALT_SIZE> generateSalt(); // Add this

    int getNextBit();
    void resetState();
    std::string lfsrProcess(const std::string& input);
    std::string computeSha256(const std::string& input); // Helper for hashing

public:
    LfsrEncryption(const std::vector<int>& taps, const std::vector<int>& init_state, const std::string& password = "");

    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& encrypted_text) override;
    std::string encryptWithSalt(const std::string& plaintext) override;
    std::string decryptWithSalt(const std::string& encrypted_text) override;
    EncryptionType getAlgorithm() const override { return EncryptionType::LFSR; }
    void setAlgorithm(EncryptionType newAlgorithm) override {} // Not supported
    void setMasterPassword(const std::string& password) override;
    std::string hash(const std::string& input) override;
};

#endif 