#include "./api.h"

#include <openssl/rand.h>

#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "../config/GlobalConfig.h"
#include "../crypto/encryption_factory.h"
#include "../crypto/lfsr_encryption.h"
#include "../crypto/rsa_encryption.h"
#include "./EncryptionParamsBuilder.h"

// Use the appropriate filesystem library
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

// Method implementations

void CredentialsManager::createEncryptor(EncryptionType type, const std::string& password) {
    encryptionType = type;
    currentMasterPassword = password;
    lfsrTaps = ConfigManager::getInstance().getLfsrTaps();
    lfsrInitState = ConfigManager::getInstance().getLfsrInitState();

    auto params = EncryptionParamsBuilder::create(type, password);
    encryptor = EncryptionFactory::create(params);
}

// Helper method implementations
bool CredentialsManager::validateCredentialInputs(const std::string& platform,
                                                  const std::string& user,
                                                  const std::string& pass) const {
    if (platform.empty()) {
        std::cerr << "Error: Platform name cannot be empty\n";
        return false;
    }
    if (user.empty()) {
        std::cerr << "Error: Username cannot be empty\n";
        return false;
    }
    if (pass.empty()) {
        std::cerr << "Error: Password cannot be empty\n";
        return false;
    }
    if (currentMasterPassword.empty()) {
        std::cerr << "Error: Must be logged in to perform this operation\n";
        return false;
    }
    return true;
}

std::unique_ptr<IEncryption> CredentialsManager::createCredentialEncryptor(const CredentialData& credData) const {
    return createCredentialEncryptor(credData.encryption_type, credData.rsa_public_key, credData.rsa_private_key);
}

std::unique_ptr<IEncryption> CredentialsManager::createCredentialEncryptor(
    EncryptionType type,
    const std::optional<std::string>& publicKey,
    const std::optional<std::string>& privateKey) const {
    std::unique_ptr<IEncryption> encryptor;

    if (type == EncryptionType::RSA) {
        auto params =
            EncryptionParamsBuilder::createRSA(currentMasterPassword, publicKey.value_or(""), privateKey.value_or(""));
        encryptor = EncryptionFactory::create(params);
    } else {
        auto params = EncryptionParamsBuilder::create(type, currentMasterPassword);
        encryptor = EncryptionFactory::create(params);
    }

    if (!encryptor) {
        throw std::runtime_error("Failed to create encryptor for type: " + std::to_string(static_cast<int>(type)));
    }

    encryptor->setMasterPassword(currentMasterPassword);
    return encryptor;
}

std::pair<std::optional<std::string>, std::optional<std::string>> CredentialsManager::extractRSAKeys(
    IEncryption* encryptor) const {
    auto rsaEncryptor = dynamic_cast<RSAEncryption*>(encryptor);
    if (!rsaEncryptor) {
        throw std::runtime_error("Failed to cast to RSAEncryption for key retrieval.");
    }

    return {rsaEncryptor->getPublicKey(), rsaEncryptor->getEncryptedPrivateKeyData()};
}

std::pair<std::string, std::string> CredentialsManager::encryptCredentialPair(IEncryption* encryptor,
                                                                              const std::string& user,
                                                                              const std::string& pass) const {
    if (auto saltedEncryptor = dynamic_cast<ISaltedEncryption*>(encryptor)) {
        std::vector<std::string> plaintexts = {user, pass};
        std::vector<std::string> ciphertexts = saltedEncryptor->encryptWithSalt(plaintexts);
        return {ciphertexts[0], ciphertexts[1]};
    } else {
        return {encryptor->encrypt(user), encryptor->encrypt(pass)};
    }
}

CredentialData CredentialsManager::createCredentialData(EncryptionType type,
                                                        const std::string& encryptedUser,
                                                        const std::string& encryptedPass,
                                                        const std::optional<std::string>& publicKey,
                                                        const std::optional<std::string>& privateKey) const {
    CredentialData credData;
    credData.encryption_type = type;
    credData.encrypted_user = encryptedUser;
    credData.encrypted_pass = encryptedPass;

    if (type == EncryptionType::RSA) {
        credData.rsa_public_key = publicKey;
        credData.rsa_private_key = privateKey;
    }

    return credData;
}

CredentialsManager::CredentialsManager(const std::string& dataPath, EncryptionType encryptionType)
    : dataPath(dataPath), storage(nullptr) {
    // Initialize storage
    storage = new JsonStorage(dataPath);

    // Initialize encryption with default parameters
    createEncryptor(encryptionType, "");
}

CredentialsManager::~CredentialsManager() {
    // unique_ptr will automatically delete the encryptor
    delete storage;
}

bool CredentialsManager::login(const std::string& password) {
    if (password.empty()) {
        return false;
    }

    // Try to verify the password
    try {
        std::string encryptedMaster = storage->getMasterPassword();
        if (encryptedMaster.empty()) {
            // No master password is set, so login should fail.
            return false;
        }

        // The stored value can be in one of these formats:
        // 1. salt$encrypted_verification_token (old format)
        // 2. salt:encrypted_verification_token (new format from migration)
        size_t delimiter = encryptedMaster.find('$');
        if (delimiter == std::string::npos) {
            // Try with colon as delimiter (new format)
            delimiter = encryptedMaster.find(':');
            if (delimiter == std::string::npos) {
                std::cerr << "Invalid format for stored master password" << std::endl;
                return false;
            }
        }

        std::string salt = encryptedMaster.substr(0, delimiter);
        std::string encryptedToken = encryptedMaster.substr(delimiter + 1);

        // Get the default encryption type for master password
        EncryptionType masterEncType = ConfigManager::getInstance().getDefaultEncryption();
        const auto& configTaps = ConfigManager::getInstance().getLfsrTaps();
        const auto& configInitState = ConfigManager::getInstance().getLfsrInitState();

        // Create a temporary encryptor for verification using master password
        std::unique_ptr<IEncryption> tempEncryptor;

        if (masterEncType == EncryptionType::LFSR) {
            // For LFSR, we must create the encryptor with the salt
            tempEncryptor = std::make_unique<LFSREncryption>(configTaps, configInitState, salt);
        } else {
            // For other types, use the builder
            auto params = EncryptionParamsBuilder::create(masterEncType, password);
            tempEncryptor = EncryptionFactory::create(params);
        }

        if (!tempEncryptor) {
            return false;
        }
        tempEncryptor->setMasterPassword(password);

        // Decrypt the token. For LFSR, the salt is already in the state.
        // For AES, the salt is part of the encrypted data.
        std::string decryptedToken = tempEncryptor->decrypt(encryptedToken);

        // If decryption was successful and the token has the expected format
        if (!decryptedToken.empty() && decryptedToken.find("verify_") == 0) {
            // Password is correct, update our main encryptor
            currentMasterPassword = password;
            createEncryptor(encryptionType, password);
            return true;
        }
    } catch (const std::exception& e) {
        std::cerr << "Login failed: " << e.what() << std::endl;
    }
    return false;
}

bool CredentialsManager::updatePassword(const std::string& newPassword) {
    try {
        if (newPassword.empty()) {
            std::cerr << "Error: Empty password provided\n";
            return false;
        }

        // Always use the default encryption type from config for master password
        EncryptionType masterEncType = ConfigManager::getInstance().getDefaultEncryption();
        const auto& configTaps = ConfigManager::getInstance().getLfsrTaps();
        const auto& configInitState = ConfigManager::getInstance().getLfsrInitState();

        // Generate a random salt
        unsigned char saltBytes[16];
        if (RAND_bytes(saltBytes, sizeof(saltBytes)) != 1) {
            throw std::runtime_error("Failed to generate random salt");
        }
        std::string saltStr(reinterpret_cast<const char*>(saltBytes), sizeof(saltBytes));

        // Create a verification token (don't store the actual password)
        std::string verificationToken = "verify_" + std::to_string(std::time(nullptr));

        std::unique_ptr<IEncryption> masterEncryptor;

        if (masterEncType == EncryptionType::LFSR) {
            // For LFSR, manually create the encryptor with the generated salt
            masterEncryptor = std::make_unique<LFSREncryption>(configTaps, configInitState, saltStr);
            masterEncryptor->setMasterPassword(newPassword);
        } else {
            // For other encryption types, use the builder
            auto params = EncryptionParamsBuilder::create(masterEncType, newPassword);
            masterEncryptor = EncryptionFactory::create(params);
        }

        if (!masterEncryptor) {
            throw std::runtime_error("Failed to create encryptor for type: " +
                                     std::to_string(static_cast<int>(masterEncType)));
        }

        // Encrypt the verification token with the new password and salt
        std::string encryptedToken = masterEncryptor->encrypt(verificationToken);

        // Store the salt and encrypted token
        return storage->updateMasterPassword(saltStr + "$" + encryptedToken);
    } catch (const EncryptionError& e) {
        std::cerr << "Encryption error during password update: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Exception during password update: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::addCredentials(const std::string& platform,
                                        const std::string& user,
                                        const std::string& pass,
                                        std::optional<EncryptionType> encryptionType) {
    try {
        // Validate inputs using helper method
        if (!validateCredentialInputs(platform, user, pass)) {
            return false;
        }

        // Use provided encryption type or default to instance type
        EncryptionType credEncType = encryptionType.value_or(this->encryptionType);

        // Create encryptor and encrypt credentials
        auto credEncryptor = createCredentialEncryptor(credEncType);
        auto encryptedPair = encryptCredentialPair(credEncryptor.get(), user, pass);

        // Handle RSA key extraction
        std::optional<std::string> publicKey, privateKey;
        if (credEncType == EncryptionType::RSA) {
            auto keys = extractRSAKeys(credEncryptor.get());
            publicKey = keys.first;
            privateKey = keys.second;
        }

        // Create credential data and store
        CredentialData credData =
            createCredentialData(credEncType, encryptedPair.first, encryptedPair.second, publicKey, privateKey);
        storage->addCredentials(platform, credData);

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error adding credentials: " << e.what() << std::endl;
        return false;
    }
}

bool CredentialsManager::deleteCredentials(const std::string& platform) {
    try {
        return storage->deleteCredentials(platform);
    } catch (const std::exception& e) {
        std::cerr << "Error deleting credentials: " << e.what() << std::endl;
        return false;
    }
}

std::optional<DecryptedCredential> CredentialsManager::getCredentials(const std::string& platform) {
    try {
        if (platform.empty()) {
            std::cerr << "Error: Empty platform name provided\n";
            return std::nullopt;
        }

        auto credentialDataOpt = storage->getCredentials(platform);
        if (!credentialDataOpt) {
            // This is not an error, just means no credentials for this platform
            return std::nullopt;
        }

        CredentialData credentialData = *credentialDataOpt;
        DecryptedCredential decryptedCredential;

        // Use helper method to create encryptor
        auto encryptor = createCredentialEncryptor(credentialData);

        // Decrypt the data using appropriate method based on encryption type
        if (auto saltedDecryptor = dynamic_cast<ISaltedEncryption*>(encryptor.get())) {
            std::vector<std::string> encrypted_data = {credentialData.encrypted_user, credentialData.encrypted_pass};
            std::vector<std::string> decrypted_data = saltedDecryptor->decryptWithSalt(encrypted_data);
            if (decrypted_data.size() == 2) {
                decryptedCredential.username = decrypted_data[0];
                decryptedCredential.password = decrypted_data[1];
            } else {
                return std::nullopt;
            }
        } else {
            decryptedCredential.username = encryptor->decrypt(credentialData.encrypted_user);
            decryptedCredential.password = encryptor->decrypt(credentialData.encrypted_pass);
        }

        return decryptedCredential;
    } catch (const std::exception& e) {
        std::cerr << "Exception while getting credentials: " << e.what() << std::endl;
        return std::nullopt;
    }
}

bool CredentialsManager::hasMasterPassword() const {
    try {
        std::string storedPassword = storage->getMasterPassword();
        return !storedPassword.empty();
    } catch (const std::exception& e) {
        std::cerr << "Exception checking master password: " << e.what() << std::endl;
        return false;
    }
}

void CredentialsManager::setEncryptionType(EncryptionType type) {
    encryptionType = type;
    if (encryptor) {
        createEncryptor(type, currentMasterPassword);
    }
}

std::vector<std::string> CredentialsManager::getAllPlatforms() const {
    if (!storage) {
        throw std::runtime_error("Storage not initialized");
    }

    try {
        return storage->getAllPlatforms();
    } catch (const std::exception& e) {
        std::cerr << "Error retrieving platforms: " << e.what() << std::endl;
        return {};
    }
}

bool CredentialsManager::updateCredentials(const std::string& platform,
                                           const std::string& user,
                                           const std::string& pass,
                                           std::optional<EncryptionType> encryptionType) {
    try {
        // Validate inputs using helper method
        if (!validateCredentialInputs(platform, user, pass)) {
            return false;
        }

        // First check if credentials exist
        auto existingCredentialData = storage->getCredentials(platform);
        if (!existingCredentialData) {
            std::cerr << "Error: No credentials found for platform: " << platform << "\n";
            return false;
        }

        // Get the existing decrypted credentials to compare
        auto existingDecryptedCreds = getCredentials(platform);
        if (!existingDecryptedCreds) {
            std::cerr << "Error: Failed to decrypt existing credentials for comparison\n";
            return false;
        }

        // Check if username, password, or encryption type has actually changed
        bool usernameChanged = (user != existingDecryptedCreds->username);
        bool passwordChanged = (pass != existingDecryptedCreds->password);
        bool encryptionChanged =
            encryptionType.has_value() && (encryptionType.value() != existingCredentialData->encryption_type);

        // If nothing changed, return success without doing work
        if (!usernameChanged && !passwordChanged && !encryptionChanged) {
            return true;
        }

        // Check if encryption type needs to be changed
        EncryptionType finalEncType = encryptionType.value_or(existingCredentialData->encryption_type);
        // Use the specified or existing encryption type to create encryptor and encrypt new data
        auto credEncryptor = createCredentialEncryptor(finalEncType);
        auto encryptedPair = encryptCredentialPair(credEncryptor.get(), user, pass);

        // Handle RSA key extraction for encryption type changes
        std::optional<std::string> publicKey, privateKey;
        if (finalEncType == EncryptionType::RSA) {
            // If changing to RSA or already RSA, get keys from the encryptor
            auto keys = extractRSAKeys(credEncryptor.get());
            publicKey = keys.first;
            privateKey = keys.second;
        } else {
            // For non-RSA encryption, preserve existing RSA keys if they exist
            publicKey = existingCredentialData->rsa_public_key;
            privateKey = existingCredentialData->rsa_private_key;
        }

        // Create updated credential data
        CredentialData credData =
            createCredentialData(finalEncType, encryptedPair.first, encryptedPair.second, publicKey, privateKey);

        // Update the credentials using the dedicated update method
        return storage->updateCredentials(platform, credData);
    } catch (const std::exception& e) {
        std::cerr << "Error updating credentials: " << e.what() << std::endl;
        return false;
    }
}
