#include "EncryptionParamsBuilder.h"

EncryptionConfigParameters EncryptionParamsBuilder::create(EncryptionType type,
                                                           const std::string& masterPassword,
                                                           const std::string& salt) {
    EncryptionConfigParameters params;
    params.type = type;
    params.masterPassword = masterPassword;
    params.lfsrTaps = ConfigManager::getInstance().getLfsrTaps();
    params.lfsrInitState = ConfigManager::getInstance().getLfsrInitState();
    params.salt = salt;

    return params;
}

EncryptionConfigParameters EncryptionParamsBuilder::createRSA(const std::string& masterPassword,
                                                              const std::string& publicKey,
                                                              const std::string& privateKey) {
    EncryptionConfigParameters params;
    params.type = EncryptionType::RSA;
    params.masterPassword = masterPassword;
    params.publicKey = publicKey;
    params.privateKey = privateKey;
    params.lfsrTaps = ConfigManager::getInstance().getLfsrTaps();
    params.lfsrInitState = ConfigManager::getInstance().getLfsrInitState();

    return params;
}
