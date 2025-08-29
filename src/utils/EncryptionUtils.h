#ifndef ENCRYPTION_UTILS_H
#define ENCRYPTION_UTILS_H

#include <vector>

#include "GlobalConfig.h"

namespace EncryptionUtils {

inline int toDropdownIndex(EncryptionType type) {
    switch (type) {
        case EncryptionType::AES:
            return 0;
        case EncryptionType::LFSR:
            return 1;
        case EncryptionType::RSA:
            return 2;
        default:
            return 0;  // Default to AES
    }
}

inline EncryptionType fromDropdownIndex(int index) {
    switch (index) {
        case 0:
            return EncryptionType::AES;
        case 1:
            return EncryptionType::LFSR;
        case 2:
            return EncryptionType::RSA;
        default:
            return EncryptionType::AES;  // Default to AES
    }
}

inline std::string encryptionTypeToString(EncryptionType type) {
    switch (type) {
        case EncryptionType::AES:
            return "AES-256";
        case EncryptionType::LFSR:
            return "LFSR";
        case EncryptionType::RSA:
            return "RSA-2048";
        default:
            return "Unknown";
    }
}

// Get display name for encryption type (for UI)
inline const char* getDisplayName(EncryptionType type) {
    switch (type) {
        case EncryptionType::AES:
            return "AES-256";
        case EncryptionType::LFSR:
            return "LFSR";
        case EncryptionType::RSA:
            return "RSA-2048";
        default:
            return "Unknown";
    }
}

// Get all available encryption types
inline std::vector<EncryptionType> getAllTypes() {
    return {EncryptionType::AES, EncryptionType::LFSR, EncryptionType::RSA};
}

// Get default encryption type
inline EncryptionType getDefault() {
    return EncryptionType::AES;
}

}  // namespace EncryptionUtils

#endif  // ENCRYPTION_UTILS_H
