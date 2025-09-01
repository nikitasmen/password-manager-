#ifndef CREDENTIAL_DATA_H
#define CREDENTIAL_DATA_H

#include <optional>
#include <string>
#include <vector>

#include "../config/GlobalConfig.h"

struct CredentialData {
    std::string encrypted_user;
    std::string encrypted_pass;
    EncryptionType encryption_type;
    std::optional<std::string> rsa_public_key;
    std::optional<std::string> rsa_private_key;
};

struct DecryptedCredential {
    std::string username;
    std::string password;
};

#endif  // CREDENTIAL_DATA_H
