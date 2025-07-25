#include "./encryption.h"
#include <stdexcept>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include "../crypto/aes_encryption.h"
#include "../crypto/lfsr_encryption.h"
#include "../crypto/rsa_encryption.h"

// Static methods
std::string Encryption::decryptMasterPassword(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& initState, const std::string& encrypted, const std::string& masterPassword) {
    auto enc = EncryptionFactory::create(type, taps, initState, masterPassword);
    if (type == EncryptionType::LFSR) {
        return enc->decryptWithSalt(encrypted);
    } else if (type == EncryptionType::AES) {
        return enc->decrypt(encrypted);
    } else if (type == EncryptionType::RSA) {
        return enc->decrypt(encrypted);
    }
    throw std::runtime_error("Unknown encryption type");
}

std::string Encryption::encryptMasterPassword(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& initState, const std::string& masterPassword) {
    auto enc = EncryptionFactory::create(type, taps, initState, masterPassword);
    if (type == EncryptionType::LFSR) {
        return enc->encryptWithSalt(masterPassword);
    } else if (type == EncryptionType::AES) {
        return enc->encrypt(masterPassword);
    } else if (type == EncryptionType::RSA) {
        return enc->encrypt(masterPassword);
    }
    throw std::runtime_error("Unknown encryption type");
}

// EncryptionManager implementation
EncryptionManager::EncryptionManager(EncryptionType algorithm) 
    : currentAlgorithm(algorithm), masterPassword("") {
    // Initialize LFSR parameters from config
    lfsrTaps = ConfigManager::getInstance().getLfsrTaps();
    lfsrInitState = ConfigManager::getInstance().getLfsrInitState();
    
    // Initialize encryptors as null - they will be created when needed
    aesEncryptor = nullptr;
    lfsrEncryptor = nullptr;
    rsaEncryptor = nullptr;
}

void EncryptionManager::initializeEncryptors() {
    if (masterPassword.empty()) {
        // Don't throw error, just return - encryptors will be initialized when password is set
        return;
    }
    
    try {
        // Initialize AES encryptor
        if (!aesEncryptor) {
            aesEncryptor = std::make_unique<AesEncryption>(masterPassword);
        }
        
        // Initialize LFSR encryptor
        if (!lfsrEncryptor && !lfsrTaps.empty() && !lfsrInitState.empty()) {
            lfsrEncryptor = std::make_unique<LfsrEncryption>(lfsrTaps, lfsrInitState, masterPassword);
        }
        
        // Initialize RSA encryptor if keys are available
        if (!rsaEncryptor && !rsaPublicKey.empty()) {
            rsaEncryptor = std::make_unique<RsaEncryption>(rsaPublicKey, rsaPrivateKey);
        }
    } catch (const std::exception& e) {
        throw EncryptionError("Failed to initialize encryptors: " + std::string(e.what()));
    }
}

Encryption* EncryptionManager::getCurrentEncryptor() {
    // Ensure encryptors are initialized
    initializeEncryptors();
    
    switch (currentAlgorithm) {
        case EncryptionType::AES:
            if (!aesEncryptor) {
                throw EncryptionError("AES encryptor not available - master password may not be set");
            }
            return aesEncryptor.get();
            
        case EncryptionType::LFSR:
            if (!lfsrEncryptor) {
                throw EncryptionError("LFSR encryptor not available - master password may not be set");
            }
            return lfsrEncryptor.get();
            
        case EncryptionType::RSA:
            if (!rsaEncryptor) {
                throw EncryptionError("RSA encryptor not available - RSA keys may not be set");
            }
            return rsaEncryptor.get();
            
        default:
            throw EncryptionError("Unknown encryption algorithm");
    }
}

std::string EncryptionManager::encrypt(const std::string& plaintext) {
    return getCurrentEncryptor()->encrypt(plaintext);
}

std::string EncryptionManager::decrypt(const std::string& encrypted_text) {
    return getCurrentEncryptor()->decrypt(encrypted_text);
}

std::string EncryptionManager::encryptWithSalt(const std::string& plaintext) {
    return getCurrentEncryptor()->encryptWithSalt(plaintext);
}

std::string EncryptionManager::decryptWithSalt(const std::string& encrypted_text) {
    return getCurrentEncryptor()->decryptWithSalt(encrypted_text);
}

void EncryptionManager::setAlgorithm(EncryptionType newAlgorithm) {
    currentAlgorithm = newAlgorithm;
    
    // If we have a master password, reinitialize encryptors for the new algorithm
    if (!masterPassword.empty()) {
        try {
            initializeEncryptors();
        } catch (const std::exception& e) {
            throw EncryptionError("Failed to switch encryption algorithm: " + std::string(e.what()));
        }
    }
}

void EncryptionManager::setMasterPassword(const std::string& password) {
    if (password.empty()) {
        throw EncryptionError("Master password cannot be empty");
    }
    
    masterPassword = password;
    
    // Reset encryptors so they get recreated with the new password
    aesEncryptor = nullptr;
    lfsrEncryptor = nullptr;
    // Note: RSA doesn't use master password, so we don't reset it
    
    // Initialize encryptors with the new password
    initializeEncryptors();
}

std::string EncryptionManager::hash(const std::string& input) {
    // Use the current encryptor's hash function
    return getCurrentEncryptor()->hash(input);
}

void EncryptionManager::setRsaKeys(const std::string& publicKey, const std::string& privateKey) {
    rsaPublicKey = publicKey;
    rsaPrivateKey = privateKey;
    
    // Reset RSA encryptor so it gets recreated with new keys
    rsaEncryptor = nullptr;
    
    // If RSA is the current algorithm, reinitialize
    if (currentAlgorithm == EncryptionType::RSA) {
        initializeEncryptors();
    }
}

std::pair<std::string, std::string> EncryptionManager::generateRsaKeys() {
    auto keyPair = RsaEncryption::generateKeyPair();
    setRsaKeys(keyPair.first, keyPair.second);
    return keyPair;
}

namespace EncryptionFactory {
    std::unique_ptr<Encryption> create(EncryptionType type, const std::vector<int>& taps, const std::vector<int>& init_state, const std::string& password, const std::string& pubKey, const std::string& privKey) {
        // Create an EncryptionManager instead of specific encryption types
        auto manager = std::make_unique<EncryptionManager>(type);
        
        // Set master password if provided
        if (!password.empty()) {
            manager->setMasterPassword(password);
        }
        
        // Set RSA keys if provided
        if (!pubKey.empty()) {
            manager->setRsaKeys(pubKey, privKey);
        }
        
        return std::move(manager);
    }
}
