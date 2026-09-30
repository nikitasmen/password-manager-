#ifndef ESP_STORE_H
#define ESP_STORE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "IVaultStore.h"

struct EspConfig {
    std::string host;      // IP or name; the cert is always verified as pwvault.local
    int port = 443;
    std::string certPath;    // pinned server cert, esp32/vault/cert.pem
    std::string clientCert;  // this device's certificate (esp32/pki.sh pair)
    std::string clientKey;   // ...and its private key (never leaves this machine)
};

// The ESP32 vault over mutual TLS: docs/PROTOCOL.md §7. The board only talks to devices whose certificate
// its device CA signed.
// Throws StoreUnavailable when the board can't be reached, std::runtime_error for anything else.
class EspStore : public IVaultStore {
   public:
    explicit EspStore(EspConfig cfg);

    std::optional<VaultMeta> getMeta() override;
    bool putMeta(const VaultMeta& meta, int ifRev) override;
    Changes changesAfter(uint64_t seq) override;
    void putEntries(const std::vector<EntryRecord>& entries) override;
    void noteAccess(const std::string& platform, const std::string& username) override;

    // Paired devices, as the board knows them. Not vault data, so not part of IVaultStore.
    struct Device {
        std::string name;
        int64_t lastSeen = 0;  // unix time of its last request since the board booted; 0 = unknown
        bool thisDevice = false;
    };
    std::vector<Device> devices();
    // Blocks until someone presses BOOT on the board (up to a minute). Throws with the board's reason if not.
    void revokeDevice(const std::string& name);

   private:
    struct Response {
        long status;
        std::string body;
    };
    Response request(const std::string& method, const std::string& path, const std::string& body = "",
                     long timeoutSeconds = 15);

    EspConfig cfg_;
    // One handle for the store's lifetime: curl keeps the TLS connection open between requests.
    // A handshake with the ESP32 costs ~0.5 s; a request on a reused connection ~0.06 s.
    std::unique_ptr<void, void (*)(void*)> curl_;
};

#endif  // ESP_STORE_H
