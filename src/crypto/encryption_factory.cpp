#include "encryption_factory.h"
#include "aes_encryption.h"
#include "lfsr_encryption.h"

using namespace std;

unique_ptr<IEncryption> EncryptionFactory::create(
    EncryptionType type,
    const vector<int>& taps,
    const vector<int>& initState,
    const string& salt) {
    
    unique_ptr<IEncryption> encryption;
    
    switch (type) {
        case EncryptionType::AES:
            encryption = make_unique<AESEncryption>();
            break;
            
        case EncryptionType::LFSR:
            encryption = make_unique<LFSREncryption>(taps, initState, salt);
            break;
            
        default:
            throw EncryptionError("Unsupported encryption type");
    }
    
    return encryption;
}

unique_ptr<IEncryption> EncryptionFactory::createForMasterPassword(
    EncryptionType type,
    const string& masterPassword,
    const vector<int>& taps,
    const vector<int>& initState) {
    
    // For LFSR, we'll pass the master password as salt to modify the initial state
    string salt = (type == EncryptionType::LFSR) ? masterPassword : "";
    
    auto encryption = create(type, taps, initState, salt);
    encryption->setMasterPassword(masterPassword);
    return encryption;
}
