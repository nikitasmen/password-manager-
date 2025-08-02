#include "./encryption.h"
#include "../crypto/encryption_factory.h"
#include "../crypto/aes_encryption.h"
#include "../crypto/lfsr_encryption.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <vector>
#include <memory>

using namespace std;

// Encryption class implementation
Encryption::Encryption(EncryptionType algorithm, 
                     const vector<int>& taps,
                     const vector<int>& initState,
                     const string& password)
    : algorithm_(algorithm), taps_(taps), initialState_(initState), masterPassword_(password) {
    
    if (algorithm_ == EncryptionType::LFSR) {
        if (taps_.empty()) {
            taps_ = {0, 2};  // Default taps for LFSR
        }
        if (initialState_.empty()) {
            initialState_ = {1, 0, 1};  // Default initial state
        }
    }
    
    // Initialize the encryptor
    updateEncryptor();
}

void Encryption::updateEncryptor() {
    EncryptionConfigParameters params;
    params.type = algorithm_;
    params.masterPassword = masterPassword_;
    params.lfsrTaps = taps_;
    params.lfsrInitState = initialState_;
    
    encryptor_ = EncryptionFactory::create(params);
    needsRecreation_ = false;
}

void Encryption::setMasterPassword(const string& password) {
    if (masterPassword_ != password) {
        masterPassword_ = password;
        needsRecreation_ = true;
    }
}

string Encryption::encrypt(const string& plaintext) {
    if (masterPassword_.empty()) {
        throw runtime_error("Master password not set");
    }
    
    if (needsRecreation_ || !encryptor_) {
        updateEncryptor();
    }
    
    try {
        return encryptor_->encrypt(plaintext);
    } catch (const exception& e) {
        throw runtime_error(string("Encryption failed: ") + e.what());
    }
}

string Encryption::decrypt(const string& ciphertext) {
    if (masterPassword_.empty()) {
        throw runtime_error("Master password not set");
    }
    
    if (needsRecreation_ || !encryptor_) {
        updateEncryptor();
    }
    
    try {
        return encryptor_->decrypt(ciphertext);
    } catch (const exception& e) {
        throw runtime_error(string("Decryption failed: ") + e.what());
    }
}

vector<string> Encryption::encryptWithSalt(const vector<string>& plaintexts) {
    if (needsRecreation_ || !encryptor_) {
        updateEncryptor();
    }
    
    try {
        if (auto saltedEncryptor = dynamic_cast<ISaltedEncryption*>(encryptor_.get())) {
            // Use the salted encryption if available
            return saltedEncryptor->encryptWithSalt(plaintexts);
        }
        
        // Fallback to regular encryption if not a salted encryptor
        vector<string> results;
        results.reserve(plaintexts.size());
        for (const auto& plaintext : plaintexts) {
            results.push_back(encrypt(plaintext));
        }
        return results;
    } catch (const exception& e) {
        throw runtime_error(string("Salted encryption failed: ") + e.what());
    }
}

vector<string> Encryption::decryptWithSalt(const vector<string>& ciphertexts) {
    if (needsRecreation_ || !encryptor_) {
        updateEncryptor();
    }
    
    try {
        if (auto saltedDecryptor = dynamic_cast<ISaltedEncryption*>(encryptor_.get())) {
            // Use the salted decryption if available
            return saltedDecryptor->decryptWithSalt(ciphertexts);
        }
        
        // Fallback to regular decryption if not a salted decryptor
        vector<string> results;
        results.reserve(ciphertexts.size());
        for (const auto& ciphertext : ciphertexts) {
            results.push_back(decrypt(ciphertext));
        }
        return results;
    } catch (const exception& e) {
        throw runtime_error(string("Salted decryption failed: ") + e.what());
    }
}

string Encryption::encryptWithSalt(const string& plaintext) {
    vector<string> plaintexts = {plaintext};
    auto results = encryptWithSalt(plaintexts);
    if (!results.empty()) {
        return results[0];
    }
    throw runtime_error("Failed to encrypt with salt: empty result");
}

string Encryption::decryptWithSalt(const string& ciphertext) {
    vector<string> ciphertexts = {ciphertext};
    auto results = decryptWithSalt(ciphertexts);
    if (!results.empty()) {
        return results[0];
    }
    throw runtime_error("Failed to decrypt with salt: empty result");
}


// Static methods for master password encryption/decryption
string Encryption::decryptMasterPassword(EncryptionType type, 
                                       const vector<int>& taps, 
                                       const vector<int>& initState, 
                                       const string& encrypted, 
                                       const string& masterPassword) {
    try {
        // Create an encryption instance with the provided parameters
        Encryption decryptor(type, taps, initState, masterPassword);
        
        // Use the salted decryption method which properly handles the salt
        return decryptor.decryptWithSalt(encrypted);
    } catch (const exception& e) {
        // Provide detailed error information while avoiding potential information leakage
        throw runtime_error("Failed to decrypt master password: " + string(e.what()));
    }
}

string Encryption::encryptMasterPassword(EncryptionType type, 
                                       const vector<int>& taps, 
                                       const vector<int>& initState, 
                                       const string& masterPassword) {
    try {
        // Create an encryption instance with the provided parameters
        Encryption encryptor(type, taps, initState, masterPassword);
        
        // Use the salted encryption method which adds a random salt
        return encryptor.encryptWithSalt(masterPassword);
    } catch (const exception& e) {
        // Provide detailed error information while avoiding potential information leakage
        throw runtime_error("Failed to encrypt master password: " + string(e.what()));
    }
}
