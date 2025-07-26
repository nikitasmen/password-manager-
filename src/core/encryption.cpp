#include "./encryption.h"
#include "../crypto/cipher_context_raii.h"
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <random>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

using namespace std;

// CipherContextRAII implementation has been moved to cipher_context_raii.h/cpp

// Helper function to convert bytes to hex
static string bytesToHex(const vector<unsigned char>& bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    for(unsigned char b : bytes) {
        ss << setw(2) << static_cast<unsigned>(b);
    }
    return ss.str();
}

// Helper function to convert hex string to bytes
static vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Generate random bytes
vector<unsigned char> generateRandomBytes(size_t length) {
    vector<unsigned char> bytes(length);
    if (RAND_bytes(bytes.data(), static_cast<int>(length)) != 1) {
        throw runtime_error("Failed to generate random bytes");
    }
    return bytes;
}

// Encryption class implementation
Encryption::Encryption(EncryptionType algorithm, 
                     const vector<int>& taps,
                     const vector<int>& initState,
                     const string& password)
    : algorithm_(algorithm), taps_(taps), 
      initialState_(initState), masterPassword_(password) {
    // Initialize OpenSSL algorithms
    OpenSSL_add_all_algorithms();
    
    // If no initial state is provided for LFSR, use a default one
    if (algorithm_ == EncryptionType::LFSR && initialState_.empty()) {
        initialState_ = {1, 0, 1, 1, 0, 1, 0, 1}; // Default initial state
    }
    
    // If no taps are provided for LFSR, use a default one
    if (algorithm_ == EncryptionType::LFSR && taps_.empty()) {
        taps_ = {0, 2}; // Default taps for LFSR
    }
}

void Encryption::setMasterPassword(const string& password) {
    masterPassword_ = password;
}

string Encryption::encrypt(const string& plaintext) {
    if (masterPassword_.empty()) {
        throw runtime_error("Master password not set");
    }
    
    try {
        auto encryptor = EncryptionFactory::createForMasterPassword(algorithm_, masterPassword_, taps_, initialState_);
        return encryptor->encrypt(plaintext);
    } catch (const exception& e) {
        throw runtime_error(string("Encryption failed: ") + e.what());
    }
}

string Encryption::decrypt(const string& ciphertext) {
    if (masterPassword_.empty()) {
        throw runtime_error("Master password not set");
    }
    
    try {
        auto decryptor = EncryptionFactory::createForMasterPassword(algorithm_, masterPassword_, taps_, initialState_);
        return decryptor->decrypt(ciphertext);
    } catch (const exception& e) {
        throw runtime_error(string("Decryption failed: ") + e.what());
    }
}

// Salt-based encryption/decryption helpers
string Encryption::encryptWithSalt(const string& plaintext) {
    // Use the standard encrypt method which now includes per-record salt for LFSR
    return encrypt(plaintext);
}

string Encryption::decryptWithSalt(const string& ciphertext) {
    // Use the standard decrypt method which now handles both old and new salt formats for LFSR
    return decrypt(ciphertext);
}



// Static methods for master password encryption/decryption
string Encryption::decryptMasterPassword(EncryptionType type, 
                                       const vector<int>& taps, 
                                       const vector<int>& initState, 
                                       const string& encrypted, 
                                       const string& masterPassword) {
    try {
        Encryption decryptor(type, taps, initState, masterPassword);
        // For master password, we use decryptWithSalt which handles the salt properly
        return decryptor.decryptWithSalt(encrypted);
    } catch (const exception& e) {
        throw runtime_error(string("Failed to decrypt master password: ") + e.what());
    }
}

string Encryption::encryptMasterPassword(EncryptionType type, 
                                       const vector<int>& taps, 
                                       const vector<int>& initState, 
                                       const string& masterPassword) {
    try {
        Encryption encryptor(type, taps, initState, masterPassword);
        // For master password, we use encryptWithSalt which adds a random salt
        return encryptor.encryptWithSalt(masterPassword);
    } catch (const exception& e) {
        throw runtime_error(string("Failed to encrypt master password: ") + e.what());
    }
}
