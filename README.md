# Password Manager

A C++17 password manager with a desktop GUI (FLTK) and a terminal UI, that keeps your vault in sync with a small **ESP32 box on your home network**. The ESP32 only ever stores ciphertext: all encryption happens on your devices, so even someone holding the board can't read your passwords.

```
 GUI (FLTK)    TUI          Python client     future mobile app
     └────┬─────┘                 │                  │
     VaultService (C++)      same protocol      same protocol     ← encryption happens here, on the client
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

Everything is declared in `shell.nix`: the C++ toolchain, FLTK, OpenSSL and curl, `arduino-cli` with a pinned ESP32 core and libraries, and Python with `cryptography`.

```bash
nix-shell                  # enters the dev shell and builds ./password_manager
./password_manager -g      # GUI
./password_manager -t      # terminal UI
./password_manager         # uses defaultUIMode from .config
```

Run it from the repo root: it reads `./.config` and `./data` relative to the working directory. Without an ESP32 configured, the app works as a local-only vault.

## Setting up the ESP32

Tested on an ESP32-D0WD with a 128×64 SSD1306 OLED (I2C, SDA 21 / SCL 22, address 0x3C). The pins are constants at the top of `esp32/vault/vault.ino`.

1. **Certificates:** all of this goes through `esp32/pki.sh`, and everything it creates is gitignored.
   ```bash
   cd esp32
   ./pki.sh server         # the board's TLS cert; every client pins vault/cert.pem
   ./pki.sh init           # your device CA; the board accepts only devices it signed
   ./pki.sh add laptop     # one certificate per device; the name is what the OLED shows
   ```
   `esp32/pki/ca.key` can issue new devices, so keep it private. Once your devices exist, keeping it offline is best.
2. **Wi-Fi:** `cp esp32/vault/secrets.example.h esp32/vault/secrets.h`, then set your SSID and password (the ESP32 only supports **2.4 GHz**).
3. **Flash:**
   ```bash
   arduino-cli compile -b esp32:esp32:esp32 --upload -p /dev/ttyUSB0 esp32/vault
   ```
   The OLED shows the clock and the board's IP. If Wi-Fi doesn't connect within 30 seconds, the board reboots and tries again.
4. **Fixed IP:** set up a DHCP reservation for the board in your router, so its address doesn't change.
5. **Point the app at it**, either in the GUI (Settings → ESP32 fields, then restart) or in `.config`:
   ```ini
   espHost=192.168.2.5
   espCert=esp32/vault/cert.pem
   espClientCert=/path/to/esp32/pki/devices/laptop.pem
   espClientKey=/path/to/esp32/pki/devices/laptop.key
   ```
   For another machine, copy it its own `.pem` and `.key` from `esp32/pki/devices/`, plus `vault/cert.pem`.
   The GUI title bar and the TUI show the sync status.

The board is a plain USB-powered device: plug it into any charger.

**Managing devices:** `./pki.sh add <name>` works without a reflash, because the board trusts anything your CA signed. To lock out a lost device, run `./pki.sh revoke <name>` and reflash. `./pki.sh list` shows every device and whether it's active.

### Using it away from home

**Don't port-forward the ESP32 to the internet.** Its TLS stack never gets security updates, and it's easy to knock offline. Instead, reach your home network over a VPN: a [Tailscale subnet router](https://tailscale.com/kb/1019/subnets) on any always-on home machine, or WireGuard on your router. The app config stays the same (use the board's LAN IP), and only your own devices can reach it.

## Configuration (`.config`)

`.config` is gitignored and saved owner-only (mode 600), because it points at this device's private key. `.config.example` is the template.

| Key | Default | Meaning |
|---|---|---|
| `dataPath` | `./data` | where `vault.json` and `sync.json` live |
| `defaultCipher` | `aes-256-gcm` | cipher preselected for new entries (`aes-256-gcm` or `chacha20-poly1305`) |
| `espHost` | *(empty)* | ESP32 IP or name; empty = local only |
| `espPort` | `443` | |
| `espCert` | `esp32/vault/cert.pem` | the board's pinned server certificate |
| `espClientCert`, `espClientKey` | | this device's certificate and private key (`esp32/pki.sh add`) |
| `defaultUIMode` | `auto` | `gui`, `tui` or `auto` |
| `clipboardTimeoutSeconds`, `autoClipboardClear` | `30`, `true` | clipboard auto-clear |
| `showEncryptionInCredentials` | `true` | show each entry's cipher when viewing it |

## Development

```bash
nix-shell
make vault_test && ./vault_test          # crypto vectors, merge rule, multi-device sync, offline, conflicts
python3 tests/protocol_vectors.py --check   # reference implementation self-check
./build.sh --tests                       # also builds and runs base64_test and vault_test
./lint.sh --all                          # clang-format + clang-tidy + cppcheck
```

`vault_test` runs sync scenarios between simulated devices, with a local file standing in for the ESP32.

**`tests/fake_esp.py`** is a local stand-in for the board: the same API, mutual TLS, revocation and merge rule, with state kept in memory. Use it to test clients (C++, Python, a future mobile app) without touching your real vault:
```bash
python3 tests/fake_esp.py --port 8443 --cert esp32/vault/cert.pem --key esp32/vault/key.pem --ca esp32/pki/ca.pem
PWVAULT_TEST_ESP="127.0.0.1:8443,$PWD/esp32/vault/cert.pem,<client .pem>,<client .key>" ./vault_test
``` To run it against a real board or the fake, set `PWVAULT_TEST_ESP="<host[:port]>,<server cert.pem>,<client .pem>,<client .key>"`. It always runs read-only checks: your certificate is accepted, a connection without one is refused, and an unreachable board counts as offline. The full sync round trip only runs on a board that doesn't hold a vault yet, and it leaves a test vault behind, so wipe the board's storage afterwards.

The test vectors come from the Python reference implementation (`clients/python/vaultproto.py`), and the C++ tests must reproduce them exactly. If you change the format, change `docs/PROTOCOL.md` first, then regenerate them with `python3 tests/protocol_vectors.py > tests/protocol_vectors.json`.

### Layout

```
docs/PROTOCOL.md        the contract: crypto format, ESP32 API, sync
src/vault/              client-side vault, no UI code
  Crypto.*                ICipher + AES-GCM / ChaCha20 (OpenSSL), PBKDF2, HMAC
  VaultFormat.*           meta, entry records, merge rule, key wrapping
  IVaultStore.h           store interface; LocalFileStore.*, EspStore.* (libcurl)
  Syncer.*                two-way sync between any two stores
  VaultService.*          the API the UIs use: unlock, get, put, remove, sync
  VaultFactory.*          builds the service from .config
src/core/UIManager.*    base class for front ends; talks only to VaultService
src/gui/, src/cli/      FLTK GUI and terminal UI
esp32/vault/            ESP32 firmware (store + OLED)
esp32/pki.sh            server cert, device CA, add/revoke devices
clients/python/         vaultproto.py (reference implementation) + pwvault CLI
tests/                  vault_test.cpp, protocol vectors, fake_esp.py (stand-in board)
```

## Python client

`clients/python/pwvault` talks to the board directly, with no local copy. It decrypts on your machine, like every client.

```bash
pwvault init                     # create the vault on an empty board (or use the desktop app)
pwvault ls
pwvault get github               # copies the password, clears the clipboard after 30 s (--show prints it)
pwvault set github nik --alg chacha20-poly1305
pwvault rm github
pwvault passwd                   # change the master password; other devices pick it up on their next sync
```

Config, `~/.config/pwvault/config.json` (chmod 600):
```json
{"host": "192.168.2.5",
 "cert": "/path/to/esp32/vault/cert.pem",
 "client_cert": "/path/to/esp32/pki/devices/NAME.pem",
 "client_key": "/path/to/esp32/pki/devices/NAME.key"}
```
Issue it its own certificate with `./pki.sh add <name>`, just like any other device.

## License

MIT, see [LICENSE](LICENSE).
