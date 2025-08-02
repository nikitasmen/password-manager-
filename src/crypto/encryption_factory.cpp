#include "encryption_factory.h"
#include "aes_encryption.h"
#include "lfsr_encryption.h"
#include "rsa_encryption.h"

using namespace std;

unique_ptr<IEncryption> EncryptionFactory::create(const EncryptionConfigParameters& params) {
    switch (params.type) {
        case EncryptionType::AES: {
            auto aes = make_unique<AESEncryption>();
            if (!params.masterPassword.empty()) {
                aes->setMasterPassword(params.masterPassword);
            }
            return aes;
        }

        case EncryptionType::LFSR: {
            auto lfsr = make_unique<LFSREncryption>(params.lfsrTaps, params.lfsrInitState, params.salt);
            if (!params.masterPassword.empty()) {
                lfsr->setMasterPassword(params.masterPassword);
            }
            return lfsr;
        }

        case EncryptionType::RSA: {
            auto rsa = make_unique<RSAEncryption>();
            if (!params.masterPassword.empty()) {
                rsa->setMasterPassword(params.masterPassword);
            }

            if (!params.publicKey.empty() && !params.privateKey.empty()) {
                // For hybrid encryption, privateKey contains encrypted private key data
                rsa->loadKeys(params.publicKey, params.privateKey);
            } else {
                // Generate new key pair for first-time use
                rsa->generateKeyPair(2048);
            }
            return rsa;
        }

        default:
            throw EncryptionError("Unsupported encryption type");
    }
}
