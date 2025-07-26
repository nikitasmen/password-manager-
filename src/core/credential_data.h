#ifndef CREDENTIAL_DATA_H
#define CREDENTIAL_DATA_H

#include <string>
#include <vector>
#include "GlobalConfig.h"

struct CredentialData {
    std::string encrypted_user;
    std::string encrypted_pass;
    EncryptionType encryption_type;
};

struct DecryptedCredential {
    std::string username;
    std::string password;
};

#endif // CREDENTIAL_DATA_H
