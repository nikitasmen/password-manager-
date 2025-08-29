#ifndef ENCRYPTION_PARAMS_BUILDER_H
#define ENCRYPTION_PARAMS_BUILDER_H

#include "../config/GlobalConfig.h"
#include "../crypto/encryption_factory.h"

/**
 * @brief Builder class for creating EncryptionConfigParameters consistently
 *
 * This class eliminates code duplication by providing a single place to build
 * encryption parameters with common defaults from the global configuration.
 */
class EncryptionParamsBuilder {
   public:
    /**
     * @brief Create encryption parameters with defaults from global config
     *
     * @param type The encryption type
     * @param masterPassword The master password
     * @param salt Optional salt (for LFSR)
     * @return EncryptionConfigParameters Ready-to-use parameters
     */
    static EncryptionConfigParameters create(EncryptionType type,
                                             const std::string& masterPassword = "",
                                             const std::string& salt = "");

    /**
     * @brief Create RSA encryption parameters with key data
     *
     * @param masterPassword The master password
     * @param publicKey The RSA public key (optional)
     * @param privateKey The RSA private key (optional)
     * @return EncryptionConfigParameters Ready-to-use RSA parameters
     */
    static EncryptionConfigParameters createRSA(const std::string& masterPassword,
                                                const std::string& publicKey = "",
                                                const std::string& privateKey = "");

   private:
    EncryptionParamsBuilder() = default;  // Static class
};

#endif  // ENCRYPTION_PARAMS_BUILDER_H
