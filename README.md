# Password Manager

A C++17 password manager with a desktop GUI (FLTK) and a terminal UI, that keeps your vault in sync with a small **ESP32 box on your home network**. The ESP32 only ever stores ciphertext: all encryption happens on your devices, so even someone holding the board can't read your passwords.

```
 GUI (FLTK)    TUI                    future mobile app
     └────┬─────┘                           │
     VaultService (C++)                same protocol       ← encryption happens here, on the client
      ├─ ICipher: AES-256-GCM | ChaCha20-Poly1305
      └─ IVaultStore ─┬─ LocalFileStore   data/vault.json (works offline)
                      └─ EspStore ────────────HTTPS──────▶ ESP32: stores encrypted records, knows no keys
                                                            OLED: clock + "laptop wants github / user nik"
```

## How it works

- **Zero-knowledge store.** Your master password unlocks a random *vault key*, and the vault key encrypts every entry. Neither ever leaves your device. The ESP32 (or a copy of `data/vault.json`) holds only encrypted blobs. Entry ids are keyed hashes of the platform name, so the store can't even tell which sites you have.
- **Local-first with automatic sync.** Every read and write goes to the local vault first, so the app works anywhere. When the ESP32 is reachable, the app syncs automatically: on unlock, after every change, and before reads once the last sync is more than 30 seconds old. Away from home it just says *ESP32 not reachable* and catches up when you're back. If two devices edit the same entry while offline, the later edit wins.
- **Pluggable ciphers.** Each entry records its own algorithm, AES-256-GCM or ChaCha20-Poly1305, which you choose when you save it. Both are authenticated, so tampering is detected. New algorithms are added by implementing `ICipher` and registering them in `makeCipher()`.
- **Changing the master password** only re-encrypts the vault key, so it's instant and propagates to your other devices on their next sync.
- **One spec, many clients.** [`docs/PROTOCOL.md`](docs/PROTOCOL.md) defines the crypto format, the ESP32 HTTP API and the sync algorithm. Any client that reproduces [`tests/protocol_vectors.json`](tests/protocol_vectors.json) byte for byte can read and write the same vault. That's how a mobile app can be added later without sharing C++ code.

### What the ESP32 protects against

| Attacker | Gets |
|---|---|
| Someone on your Wi-Fi | Nothing: HTTPS with a pinned certificate |
| A device without a certificate from your device CA | Nothing: the TLS handshake is refused before any request |
| A revoked device | `403` on every request |
| One of your devices | Ciphertext only; still needs your master password |
| Someone who steals the board | Ciphertext only; offline brute force at 600,000 PBKDF2 rounds per guess. **A strong master password is what protects you here.** |

A revoked device still completes the TLS handshake, but it gets a single `403` and then the board closes the connection. Refusing it inside the handshake would need a certificate revocation list, which ESP-IDF's TLS layer doesn't expose.

The board has no button yet, so reads are approved automatically and only *shown* on the OLED. The platform and username shown there are a display hint sent by the client, not something the board can verify.

## Quick start

Everything is declared in `shell.nix`: the C++ toolchain, FLTK, OpenSSL and curl, `arduino-cli` with a pinned ESP32 core and libraries, and Python for the fake board.

```bash
nix-shell                  # enters the dev shell and builds ./password_manager
./password_manager -g      # GUI
./password_manager -t      # terminal UI
./password_manager         # uses defaultUIMode from ~/.config/pwvault/config
```

Run it from anywhere. Settings live in `~/.config/pwvault/config` and the local vault in `~/.local/share/pwvault/` (see [Configuration](#configuration)). Without an ESP32 configured, the app works as a local-only vault.

## Setting up the ESP32

Tested on an ESP32-D0WD with a 128×64 SSD1306 OLED (I2C, SDA 21 / SCL 22, address 0x3C). The pins are constants at the top of `esp32/vault/vault.ino`.

1. **Certificates:** all of this goes through `esp32/pki.sh`, and everything it creates is gitignored.
   ```bash
   cd esp32
   ./pki.sh server         # the board's TLS cert; every client pins it
   ./pki.sh init           # your device CA; the board accepts only devices it signed
   ./pki.sh install laptop # makes THIS machine a device named "laptop" (the name the OLED shows)
   ```
   `esp32/pki/ca.key` can issue new devices, so keep it private. Once your devices exist, keeping it offline is best.
2. **Wi-Fi:** `cp esp32/vault/secrets.example.h esp32/vault/secrets.h`, then set your SSID and password (the ESP32 only supports **2.4 GHz**).
3. **Flash:**
   ```bash
   arduino-cli compile -b esp32:esp32:esp32 --upload -p /dev/ttyUSB0 esp32/vault
   ```
   The OLED shows the clock and the board's IP. If Wi-Fi doesn't connect within 30 seconds, the board reboots and tries again.
4. **Fixed IP:** set up a DHCP reservation for the board in your router, so its address doesn't change.
5. **Point the app at it:** set `espHost=<IP on the OLED>` in `~/.config/pwvault/config`, or in the GUI under Settings (then restart). That's all, because `pki.sh install` put the certificate files where the app looks by default.

### Adding another device

Two commands, like pairing a Bluetooth device:

```bash
# on the machine with your CA
esp32/pki.sh enroll desktop
#   enrollment file: desktop.pwvault
#   one-time code:   c5a9-d4bc-9598-e964

# copy desktop.pwvault to the new machine any way you like, then on it:
esp32/pki.sh import desktop.pwvault      # asks for the code
#   this machine is now 'desktop'
#   ✓ board at 192.168.2.5 accepts this device; start the app and unlock with your master password
```

The file holds the device's certificate and key, the board's certificate, and the board's address (taken from your config). It's encrypted with the one-time code: without the code it's useless, so USB, `scp` or a cloud folder are all fine for moving it. Delete it after importing. Then start the app on the new machine: it finds the vault on the board and asks for your existing master password. The board needs no reflash.
   The GUI title bar and the TUI show the sync status.

The board is a plain USB-powered device: plug it into any charger.

**Managing devices:** to lock out a lost device, run `./pki.sh revoke <name>` and reflash. `./pki.sh list` shows every device and whether it's active.

### Using it away from home

**Don't port-forward the ESP32 to the internet.** Its TLS stack never gets security updates, and it's easy to knock offline. Instead, reach your home network over a VPN: a [Tailscale subnet router](https://tailscale.com/kb/1019/subnets) on any always-on home machine, or WireGuard on your router. The app config stays the same (use the board's LAN IP), and only your own devices can reach it.

## Configuration

Every front end (GUI and TUI) uses the same locations, whatever directory you start it from ([XDG](https://specifications.freedesktop.org/basedir-spec/latest/)):

```
~/.config/pwvault/            $XDG_CONFIG_HOME/pwvault
  config                      key=value settings (created with defaults on first run, mode 600)
  server.pem                  the board's pinned certificate    ┐
  device.pem, device.key      this device's certificate + key   ┘ esp32/pki.sh install <name>
~/.local/share/pwvault/       $XDG_DATA_HOME/pwvault
  vault.json, sync.json       local encrypted copy + sync cursors
```

Relative paths in `config` resolve against `~/.config/pwvault/`, and `~` is expanded. [`config.example`](config.example) is the template.

| Key | Default | Meaning |
|---|---|---|
| `espHost` | *(empty)* | ESP32 IP or name; empty = local only |
| `espPort` | `443` | |
| `espCert` | `server.pem` | the board's pinned server certificate |
| `espClientCert`, `espClientKey` | `device.pem`, `device.key` | this device's certificate and private key |
| `dataPath` | *(empty)* = `~/.local/share/pwvault` | where `vault.json` and `sync.json` live |
| `defaultCipher` | `aes-256-gcm` | cipher preselected for new entries (`aes-256-gcm` or `chacha20-poly1305`) |
| `defaultUIMode` | `auto` | `gui`, `tui` or `auto` |
| `clipboardTimeoutSeconds`, `autoClipboardClear` | `30`, `true` | clipboard auto-clear |
| `showEncryptionInCredentials` | `true` | show each entry's cipher when viewing it |

## Development

```bash
nix-shell
make vault_test && ./vault_test          # crypto vectors, merge rule, multi-device sync, offline, conflicts
./build.sh --tests                       # also builds and runs base64_test and vault_test
./lint.sh --all                          # clang-format + clang-tidy + cppcheck
```

`vault_test` runs sync scenarios between simulated devices, with a local file standing in for the ESP32.

**`tests/fake_esp.py`** is a local stand-in for the board: the same API, mutual TLS, revocation and merge rule, with state kept in memory. Use it to test clients (the desktop app, a future mobile app) without touching your real vault:
```bash
python3 tests/fake_esp.py --port 8443 --cert esp32/vault/cert.pem --key esp32/vault/key.pem --ca esp32/pki/ca.pem
PWVAULT_TEST_ESP="127.0.0.1:8443,$PWD/esp32/vault/cert.pem,<client .pem>,<client .key>" ./vault_test
``` To run it against a real board or the fake, set `PWVAULT_TEST_ESP="<host[:port]>,<server cert.pem>,<client .pem>,<client .key>"`. It always runs read-only checks: your certificate is accepted, a connection without one is refused, and an unreachable board counts as offline. The full sync round trip only runs on a board that doesn't hold a vault yet, and it leaves a test vault behind, so wipe the board's storage afterwards.

`tests/protocol_vectors.json` is a fixed reference, produced by an independent Python implementation, that the C++ code reproduces byte for byte. Any other client should reproduce it too. If you ever change the format on purpose, change `docs/PROTOCOL.md` first and add new vectors alongside the old ones.

### Layout

```
docs/PROTOCOL.md        the contract: crypto format, ESP32 API, sync
src/vault/              client-side vault, no UI code
  Crypto.*                ICipher + AES-GCM / ChaCha20 (OpenSSL), PBKDF2, HMAC
  VaultFormat.*           meta, entry records, merge rule, key wrapping
  IVaultStore.h           store interface; LocalFileStore.*, EspStore.* (libcurl)
  Syncer.*                two-way sync between any two stores
  VaultService.*          the API the UIs use: unlock, get, put, remove, sync
  VaultFactory.*          builds the service from the config
src/core/UIManager.*    base class for front ends; talks only to VaultService
src/gui/, src/cli/      FLTK GUI and terminal UI
esp32/vault/            ESP32 firmware (store + OLED)
esp32/pki.sh            server cert, device CA, add/revoke devices
tests/                  vault_test.cpp, protocol vectors, fake_esp.py (stand-in board)
```

## License

MIT, see [LICENSE](LICENSE).
