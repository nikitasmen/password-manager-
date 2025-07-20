#include <iostream>
#include <vector>
#include "src/config/MigrationHelper.h"
#include "src/config/GlobalConfig.h"
#include "src/core/json_storage.h"
#include "src/core/encryption.h"

void demonstrateMigration() {
    std::cout << "=== Password Manager Migration Demo ===" << std::endl;
    
    // Set up initial LFSR settings
    std::vector<int> oldTaps = {0, 2};
    std::vector<int> oldInitState = {1, 0, 1};
    
    // New LFSR settings to migrate to
    std::vector<int> newTaps = {1, 3};
    std::vector<int> newInitState = {1, 1, 0, 1};
    
    std::string masterPassword = "test123";
    std::string dataPath = "./data";
    
    std::cout << "Old LFSR Taps: ";
    for (int tap : oldTaps) std::cout << tap << " ";
    std::cout << std::endl;
    
    std::cout << "Old LFSR Initial State: ";
    for (int state : oldInitState) std::cout << state << " ";
    std::cout << std::endl;
    
    std::cout << "New LFSR Taps: ";
    for (int tap : newTaps) std::cout << tap << " ";
    std::cout << std::endl;
    
    std::cout << "New LFSR Initial State: ";
    for (int state : newInitState) std::cout << state << " ";
    std::cout << std::endl;
    
    std::cout << "\n--- Testing Migration ---" << std::endl;
    
    // Create some test credentials with old LFSR settings
    try {
        JsonStorage storage(dataPath);
        Encryption oldLfsrEncryption(EncryptionType::LFSR, oldTaps, oldInitState, masterPassword);
        Encryption oldAesLfsrEncryption(EncryptionType::AES_LFSR, oldTaps, oldInitState, masterPassword);
        
        // Add some test credentials
        std::string testUser = "testuser";
        std::string testPass = "testpass";
        
        // LFSR encrypted credential
        std::string encryptedUser1 = oldLfsrEncryption.encryptWithSalt(testUser);
        std::string encryptedPass1 = oldLfsrEncryption.encryptWithSalt(testPass);
        storage.addCredentials("test_platform_lfsr", encryptedUser1, encryptedPass1, static_cast<int>(EncryptionType::LFSR));
        
        // AES_LFSR encrypted credential
        std::string encryptedUser2 = oldAesLfsrEncryption.encrypt(testUser + "2");
        std::string encryptedPass2 = oldAesLfsrEncryption.encrypt(testPass + "2");
        storage.addCredentials("test_platform_aes_lfsr", encryptedUser2, encryptedPass2, static_cast<int>(EncryptionType::AES_LFSR));
        
        // Pure AES credential (should not be affected by migration)
        Encryption aesEncryption(EncryptionType::AES, {}, {}, masterPassword);
        std::string encryptedUser3 = aesEncryption.encrypt(testUser + "3");
        std::string encryptedPass3 = aesEncryption.encrypt(testPass + "3");
        storage.addCredentials("test_platform_aes", encryptedUser3, encryptedPass3, static_cast<int>(EncryptionType::AES));
        
        // Set a master password
        std::string encryptedMasterPassword = oldLfsrEncryption.encryptWithSalt(masterPassword);
        storage.updateMasterPassword(encryptedMasterPassword);
        
        std::cout << "Created test credentials with old LFSR settings" << std::endl;
        
        // Now perform migration
        MigrationHelper& migrationHelper = MigrationHelper::getInstance();
        bool success = migrationHelper.migrateCredentialsForLfsrChange(
            oldTaps, oldInitState, newTaps, newInitState, masterPassword, dataPath);
        
        if (success) {
            std::cout << "\n✓ Migration completed successfully!" << std::endl;
            
            // Test that we can decrypt with new settings
            Encryption newLfsrEncryption(EncryptionType::LFSR, newTaps, newInitState, masterPassword);
            Encryption newAesLfsrEncryption(EncryptionType::AES_LFSR, newTaps, newInitState, masterPassword);
            
            // Test LFSR credential
            auto credentials1 = storage.getCredentials("test_platform_lfsr");
            if (credentials1.size() >= 2) {
                try {
                    std::string decryptedUser1 = newLfsrEncryption.decryptWithSalt(credentials1[0]);
                    std::string decryptedPass1 = newLfsrEncryption.decryptWithSalt(credentials1[1]);
                    std::cout << "✓ LFSR credential successfully decrypted: " << decryptedUser1 << std::endl;
                } catch (const std::exception& e) {
                    std::cout << "✗ Failed to decrypt LFSR credential: " << e.what() << std::endl;
                }
            }
            
            // Test AES_LFSR credential
            auto credentials2 = storage.getCredentials("test_platform_aes_lfsr");
            if (credentials2.size() >= 2) {
                try {
                    std::string decryptedUser2 = newAesLfsrEncryption.decrypt(credentials2[0]);
                    std::string decryptedPass2 = newAesLfsrEncryption.decrypt(credentials2[1]);
                    std::cout << "✓ AES_LFSR credential successfully decrypted: " << decryptedUser2 << std::endl;
                } catch (const std::exception& e) {
                    std::cout << "✗ Failed to decrypt AES_LFSR credential: " << e.what() << std::endl;
                }
            }
            
            // Test that AES credential is unchanged
            auto credentials3 = storage.getCredentials("test_platform_aes");
            if (credentials3.size() >= 2) {
                try {
                    std::string decryptedUser3 = aesEncryption.decrypt(credentials3[0]);
                    std::string decryptedPass3 = aesEncryption.decrypt(credentials3[1]);
                    std::cout << "✓ AES credential unchanged: " << decryptedUser3 << std::endl;
                } catch (const std::exception& e) {
                    std::cout << "✗ AES credential corrupted: " << e.what() << std::endl;
                }
            }
            
        } else {
            std::cout << "\n✗ Migration failed!" << std::endl;
        }
        
        // Clean up test data
        storage.deleteCredentials("test_platform_lfsr");
        storage.deleteCredentials("test_platform_aes_lfsr");
        storage.deleteCredentials("test_platform_aes");
        
    } catch (const std::exception& e) {
        std::cout << "Error during migration demo: " << e.what() << std::endl;
    }
}

int main() {
    demonstrateMigration();
    return 0;
}
