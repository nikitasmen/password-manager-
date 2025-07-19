#include "GlobalConfig.h"
#include <vector>

// Updated to use data directory inside the build folder
std::string g_data_path = "./data";  // Data stored in build/data when executables run from build directory
std::vector<int> taps = {0, 2};          // Taps for a 3-bit LFSR (x^3 + x^1 + 1)
std::vector<int> init_state = {1, 0, 1}; // Initial state [1, 0, 1]
EncryptionType g_encryption_type = EncryptionType::LFSR; // Default to LFSR for backward compatibility

// Implementation of EncryptionUtils helper functions
namespace EncryptionUtils {
    
    const char* getDisplayName(EncryptionType type) {
        switch (type) {
            case EncryptionType::LFSR:
                return "LFSR (Basic)";
            case EncryptionType::AES:
                return "AES-256 (Strong)";
            case EncryptionType::AES_LFSR:
                return "AES-256 with LFSR (Strongest)";
            default:
                return "Unknown";
        }
    }
    
    std::vector<EncryptionType> getAllTypes() {
        std::vector<EncryptionType> types;
        for (int i = 0; i < static_cast<int>(EncryptionType::COUNT); ++i) {
            types.push_back(static_cast<EncryptionType>(i));
        }
        return types;
    }
    
    EncryptionType fromDropdownIndex(int index) {
        if (index >= 0 && index < static_cast<int>(EncryptionType::COUNT)) {
            return static_cast<EncryptionType>(index);
        }
        return getDefault(); // Fallback to default if invalid index
    }
    
    int toDropdownIndex(EncryptionType type) {
        return static_cast<int>(type);
    }
    
    EncryptionType getDefault() {
        return EncryptionType::AES_LFSR; // Default to strongest encryption for new users
    }
}