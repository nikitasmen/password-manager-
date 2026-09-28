#ifndef ENCRYPTION_UTILS_H
#define ENCRYPTION_UTILS_H

// UI helpers for choosing a cipher: dropdown index <-> CipherAlg, display names.

#include <vector>

#include "../config/GlobalConfig.h"
#include "../vault/Crypto.h"

namespace encryption_utils {

inline const std::vector<CipherAlg>& getAllTypes() {
    return allCiphers();
}

inline const char* getDisplayName(CipherAlg alg) {
    switch (alg) {
        case CipherAlg::Aes256Gcm:
            return "AES-256-GCM";
        case CipherAlg::ChaCha20Poly1305:
            return "ChaCha20-Poly1305";
    }
    return "Unknown";
}

inline int toDropdownIndex(CipherAlg alg) {
    const auto& all = allCiphers();
    for (size_t i = 0; i < all.size(); ++i)
        if (all[i] == alg) return static_cast<int>(i);
    return 0;
}

inline CipherAlg fromDropdownIndex(int index) {
    const auto& all = allCiphers();
    return index >= 0 && static_cast<size_t>(index) < all.size() ? all[index] : all[0];
}

inline CipherAlg getDefault() {
    return ConfigManager::getInstance().getConfig().defaultCipher;
}

}  // namespace encryption_utils

#endif  // ENCRYPTION_UTILS_H
