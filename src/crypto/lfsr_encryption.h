#ifndef LFSR_ENCRYPTION_H
#define LFSR_ENCRYPTION_H

#include "salted_encryption.h"
#include <vector>
#include <string>
#include <random>
#include <mutex>

/**
 * @brief LFSR (Linear Feedback Shift Register) based encryption implementation
 */
class LFSREncryption : public ISaltedEncryption {
public:
    /**
     * @brief Construct a new LFSREncryption object
     * 
     * @param taps Feedback taps for the LFSR
     * @param initialState Initial state of the LFSR
     */
    LFSREncryption(const std::vector<int>& taps, const std::vector<int>& initialState, const std::string& salt = "");
    
    // IEncryption interface implementation
    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& ciphertext) override;
    std::string generateRandomSalt(size_t length = 16);
    EncryptionType getType() const override { return EncryptionType::LFSR; }
    void setMasterPassword(const std::string& password) override;

    // ISaltedEncryption interface implementation
    std::vector<std::string> encryptWithSalt(const std::vector<std::string>& plaintexts) override;
    std::vector<std::string> decryptWithSalt(const std::vector<std::string>& ciphertexts) override;
    
private:
    void applySaltToState(const std::string& salt);

private:
    int getNextBit();
    void resetState();
    std::string process(const std::string& input);
    
    std::vector<int> taps_;
    std::vector<int> state_;
    std::vector<int> initialState_;
    std::string salt_;
    std::string masterPassword_;
    std::mt19937 rng_;
    std::mutex stateMutex_;
};

#endif // LFSR_ENCRYPTION_H
