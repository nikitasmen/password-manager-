#ifndef ENCRYPTION_UTILS_H
#define ENCRYPTION_UTILS_H

#include "GlobalConfig.h"

namespace EncryptionUtils {

inline int toDropdownIndex(EncryptionType type) {
    switch (type) {
        case EncryptionType::AES:
            return 0;
        case EncryptionType::LFSR:
            return 1;
        default:
            return 0; // Default to AES
    }
}

inline EncryptionType fromDropdownIndex(int index) {
    switch (index) {
        case 0:
            return EncryptionType::AES;
        case 1:
            return EncryptionType::LFSR;
        default:
            return EncryptionType::AES; // Default to AES
    }
}

}

#endif // ENCRYPTION_UTILS_H
