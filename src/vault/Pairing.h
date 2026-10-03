#ifndef PAIRING_H
#define PAIRING_H

#include <stdexcept>
#include <string>

// Pairing this device with the ESP32: the client side of the board's pairing mode (protocol in the header comment
// of esp32/vault/vault.ino), the same as `esp32/pki.sh pair`. The device key is made here and never leaves.

constexpr int kPairPort = 8444;

// What this device needs to talk to the board, as PEM: the board's cert (to pin) and this device's cert + key.
struct PairedFiles {
    std::string serverPem, certPem, keyPem;
};

// The message is a sentence for the user.
class PairError : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
};

bool validDeviceName(const std::string& name);  // 1-20 chars of a-z 0-9 -, first not '-' (it's shown on the OLED)
// The code as typed ("abcd-o123 ...") -> the 16-char key; "" if it isn't 16 chars
std::string normalizePairCode(const std::string& typed);

// A host's id (PROTOCOL.md §8): hex SHA-256 of the DER of its server cert, given as PEM. "" if it isn't one.
std::string certFingerprint(const std::string& pem);

// Blocks until the board answers: up to ~90 s, because someone has to press BOOT to approve.
PairedFiles pairWithBoard(const std::string& host, int pairPort, const std::string& name, const std::string& code);

#endif  // PAIRING_H
