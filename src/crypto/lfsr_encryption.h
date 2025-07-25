#ifndef LFSR_ENCRYPTION_H
#define LFSR_ENCRYPTION_H

#include "encryption_interface.h"
#include <vector>
#include <random>
#include <mutex>

/**
 * @brief LFSR (Linear Feedback Shift Register) based encryption implementation
 */
class LFSREncryption : public IEncryption {
public:
    /**
     * @brief Construct a new LFSREncryption object
     * 
     * @param taps Feedback taps for the LFSR
     * @param initialState Initial state of the LFSR
     */
    LFSREncryption(const std::vector<int>& taps, const std::vector<int>& initialState);
    
    // IEncryption interface implementation
    std::string encrypt(const std::string& plaintext) override;
    std::string decrypt(const std::string& ciphertext) override;
    EncryptionType getType() const override { return EncryptionType::LFSR; }
    void setMasterPassword(const std::string& password) override { /* Not used in LFSR */ }

private:
    int getNextBit();
    void resetState();
    std::string process(const std::string& input);
    
    std::vector<int> taps_;
    std::vector<int> state_;
    std::vector<int> initialState_;
    std::mt19937 rng_;
    std::mutex stateMutex_;
};

#endif // LFSR_ENCRYPTION_H
