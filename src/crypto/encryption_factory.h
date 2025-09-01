#ifndef ENCRYPTION_FACTORY_H
#define ENCRYPTION_FACTORY_H

#include <memory>
#include <vector>

#include "encryption_interface.h"

/**
 * @brief Parameters for creating an encryption instance
 */
struct EncryptionConfigParameters {
    EncryptionType type{};
    std::string masterPassword{};
    std::string publicKey{};
    std::string privateKey{};  // For RSA: contains encrypted private key data
    std::vector<int> lfsrTaps{};
    std::vector<int> lfsrInitState{};
    std::string salt{};
};

/**
 * @brief Factory class for creating encryption instances
 */
class EncryptionFactory {
   public:
    /**
     * @brief Creates an encryption instance based on the specified parameters
     *
     * @param params The parameters for creating the encryption instance
     * @return std::unique_ptr<IEncryption> The encryption instance
     */
    static std::unique_ptr<IEncryption> create(const EncryptionConfigParameters& params);
};

#endif  // ENCRYPTION_FACTORY_H
