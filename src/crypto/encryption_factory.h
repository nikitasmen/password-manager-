#ifndef ENCRYPTION_FACTORY_H
#define ENCRYPTION_FACTORY_H

#include "encryption_interface.h"
#include <memory>
#include <vector>

/**
 * @brief Factory class for creating encryption instances
 */
class EncryptionFactory {
public:
    /**
     * @brief Creates an encryption instance based on the specified type
     * 
     * @param type The type of encryption to create
     * @param taps Taps for LFSR (only used if type is LFSR)
     * @param initState Initial state for LFSR (only used if type is LFSR)
     * @param salt Optional salt for key derivation (used by LFSR)
     * @return std::unique_ptr<IEncryption> The encryption instance
     */
    static std::unique_ptr<IEncryption> create(
        EncryptionType type,
        const std::vector<int>& taps = {},
        const std::vector<int>& initState = {},
        const std::string& salt = "");
    
    /**
     * @brief Creates an encryption instance for the master password
     * 
     * @param type The type of encryption to create
     * @param masterPassword The master password to use
     * @param taps Taps for LFSR (only used if type is LFSR)
     * @param initState Initial state for LFSR (only used if type is LFSR)
     * @return std::unique_ptr<IEncryption> The encryption instance
     */
    static std::unique_ptr<IEncryption> createForMasterPassword(
        EncryptionType type,
        const std::string& masterPassword,
        const std::vector<int>& taps = {},
        const std::vector<int>& initState = {});
};

#endif // ENCRYPTION_FACTORY_H
