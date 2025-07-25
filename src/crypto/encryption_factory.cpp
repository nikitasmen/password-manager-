#include "encryption_factory.h"
#include "aes_encryption.h"
#include "lfsr_encryption.h"

using namespace std;

unique_ptr<IEncryption> EncryptionFactory::create(
    EncryptionType type,
    const vector<int>& taps,
    const vector<int>& initState) {
    
    unique_ptr<IEncryption> encryption;
    
    switch (type) {
        case EncryptionType::AES:
            encryption = make_unique<AESEncryption>();
            break;
            
        case EncryptionType::LFSR:
            encryption = make_unique<LFSREncryption>(taps, initState);
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
    
    auto encryption = create(type, taps, initState);
    encryption->setMasterPassword(masterPassword);
    return encryption;
}
