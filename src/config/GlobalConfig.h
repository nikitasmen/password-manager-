#ifndef GLOBALCONFIG_H
#define GLOBALCONFIG_H

#include <string>
#include <vector>
#include <map>

// Global configuration constants
const int MAX_LOGIN_ATTEMPTS = 3;  // Maximum allowed login attempts before exiting

// Encryption algorithm options
enum class EncryptionType {
    LFSR = 0,       // Linear Feedback Shift Register (basic)
    AES = 1,        // Advanced Encryption Standard (stronger)
    AES_LFSR = 2,   // AES followed by LFSR (strongest - dual layer)
    
    // Keep this as the last entry to track count
    COUNT
};

// Helper functions for encryption type management
namespace EncryptionUtils {
    // Get human-readable name for an encryption type
    const char* getDisplayName(EncryptionType type);
    
    // Get all available encryption types
    std::vector<EncryptionType> getAllTypes();
    
    // Convert dropdown index to encryption type
    EncryptionType fromDropdownIndex(int index);
    
    // Convert encryption type to dropdown index
    int toDropdownIndex(EncryptionType type);
    
    // Get default encryption type
    EncryptionType getDefault();
    
    // Get encryption type mapping for menu choices
    const std::map<int, EncryptionType>& getChoiceMapping();
}

// Global variables
extern std::string g_data_path;  // Declare the global variable
extern std::vector<int> taps;    // Taps for a 3-bit LFSR (x^3 + x^1 + 1)
extern std::vector<int> init_state; // Initial state [1, 0, 1]
extern EncryptionType g_encryption_type; // Current encryption algorithm
#endif // GLOBALCONFIG_H
