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

// The host refused this device's certificate: revoked, or replaced by a newer pairing (403 "device revoked").
class DeviceRevoked : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
};

// The ESP32 vault over mutual TLS: docs/PROTOCOL.md §7. The board only talks to devices whose certificate
// its device CA signed.
// Throws StoreUnavailable when the board can't be reached, std::runtime_error for anything else.
class EspStore : public IVaultStore {
   public:
    explicit EspStore(EspConfig cfg);
    void setHost(const std::string& host, int port) {  // e.g. the user corrected the address in the connector
        cfg_.host = host;
        cfg_.port = port;
    }

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
    // The board's flash for the vault (PROTOCOL.md §7). total 0 = firmware too old to say.
    struct Storage {
        uint64_t used = 0, total = 0, records = 0;
    };
    // role: the host's role (PROTOCOL.md §6), "dedicated" when the firmware is too old to say.
    std::vector<Device> devices(Storage* storage = nullptr, std::string* role = nullptr);
    // Asks the board, then waits until someone presses BOOT there (up to a minute). Throws if it doesn't happen.
    // Revoking this device itself returns once the board refuses it.
    void revokeDevice(const std::string& name);

    // Opens pairing on the board, as a BOOT press does, so this device can show the code as a large QR for a phone
    // (PROTOCOL.md §9). The new device still needs a BOOT press on the board to be approved.
    struct PairInvite {
        std::string code;  // 16 characters
        std::string qr;    // the text to encode, PWVAULT:<ip>:<code>
        int seconds = 0;   // until pairing closes
    };
    PairInvite openPairing();

    // PIN unlock (PinUnlock.h). The board keeps one PIN record per device.
    std::string setPin(const std::string& verifierHex);  // returns the board's secret for this device
    struct PinReply {
        enum { Ok, Wrong, Removed, NotSet } result;
        std::string secretHex;  // Ok
        int triesLeft = 0;      // Wrong
    };
    PinReply tryPin(const std::string& proofHex);

   private:
    struct Response {
        long status;
        std::string body;
    };
    Response request(const std::string& method, const std::string& path, const std::string& body = "");

    EspConfig cfg_;
    // One handle for the store's lifetime: curl keeps the TLS connection open between requests.
    // A handshake with the ESP32 costs ~0.5 s; a request on a reused connection ~0.06 s.
    std::unique_ptr<void, void (*)(void*)> curl_;
};

#endif  // ESP_STORE_H
