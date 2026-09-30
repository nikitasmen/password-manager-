# Password Manager

A C++17 password manager with a desktop GUI (FLTK) and a terminal UI, that keeps your vault in sync with a small **ESP32 box on your home network**. The ESP32 only ever stores ciphertext: all encryption happens on your devices, so even someone holding the board can't read your passwords.

```
 GUI (FLTK)    TUI                    Android app    
     └────┬─────┘                           │
     VaultService (C++)                same protocol       ← encryption happens here, on the client
      ├─ ICipher: AES-256-GCM | ChaCha20-Poly1305
      └─ IVaultStore ─┬─ LocalFileStore   data/vault.json (works offline)
                      └─ EspStore ────────────HTTPS──────▶ ESP32: stores encrypted records, knows no keys
                                                            OLED: clock + "laptop wants github / user nik"
```

## How it works

- **Zero-knowledge store.** Your master password unlocks a random *vault key*, and the vault key encrypts every entry. Neither ever leaves your device. The ESP32 (or a copy of `data/vault.json`) holds only encrypted blobs. Entry ids are keyed hashes of the platform name, so stored records don't reveal which sites you have (reads do: the OLED hint sends the platform and username of each entry you open).
- **Local-first with automatic sync.** Every read and write goes to the local vault first, so the app works anywhere. When the ESP32 is reachable, the app syncs automatically: on unlock, after every change, and before reads once the last sync is more than 30 seconds old. Away from home it just says *ESP32 not reachable* and catches up when you're back. If two devices edit the same entry while offline, the later edit wins.
- **Pluggable ciphers.** Each entry records its own algorithm, AES-256-GCM or ChaCha20-Poly1305, which you choose when you save it. Both are authenticated, so tampering is detected. New algorithms are added by implementing `ICipher` and registering them in `makeCipher()`.
- **Changing the master password** only re-encrypts the vault key, so it's instant and propagates to your other devices on their next sync.
- **One spec, many clients.** [`docs/PROTOCOL.md`](docs/PROTOCOL.md) defines the crypto format, the ESP32 HTTP API and the sync algorithm. Any client that reproduces [`tests/protocol_vectors.json`](tests/protocol_vectors.json) byte for byte can read and write the same vault. That's how the Android app (`android/`) works with the same vault without sharing C++ code.

### What the ESP32 protects against

| Attacker | Gets |
|---|---|
| Someone on your Wi-Fi | Nothing: HTTPS with a pinned certificate |
| A device without a certificate from your device CA | Nothing: the TLS handshake is refused before any request |
| A revoked device | `403` on every request |
| One of your devices | Ciphertext only; still needs your master password |
| Someone who steals the board | Ciphertext only; offline brute force at 600,000 PBKDF2 rounds per guess. **A strong master password is what protects you here.** |
| Someone who steals the board **and** a device with a PIN set | The vault, if the PIN is short: the board's flash isn't encrypted, so its PIN secret plus the device's `pin.json` allow an offline PIN brute force with no try limit. Use a long PIN, or none, if both could be stolen together. |

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

1. **Server certificate:** `esp32/pki.sh server` makes the board's TLS cert (gitignored). Every client pins it.
2. **Wi-Fi:** `cp esp32/vault/secrets.example.h esp32/vault/secrets.h`, then set your SSID and password (the ESP32 only supports **2.4 GHz**).
3. **Flash:**
   ```bash
   arduino-cli compile -b esp32:esp32:esp32 --upload -p /dev/ttyUSB0 esp32/vault
   ```
   The OLED shows the clock and the board's IP. If Wi-Fi doesn't connect within 30 seconds, the board reboots and tries again. On first boot the board makes its own device CA, which never leaves it.
4. **Fixed IP:** set up a DHCP reservation for the board in your router, so its address doesn't change.
5. **Pair each device**, the first one included (see below). Pairing puts the certificate files where the app looks by default and sets `espHost`.

### Pairing a device

Only the board and the new device are involved, like pairing a Bluetooth device.

**In the app:** set the board's address (Settings, or `espHost` in the config). On every start, until this computer is connected, the app opens a **Connect to your ESP32** window (the TUI shows the same as a screen): press BOOT on the board, type the code it shows, press Pair, then press BOOT again. If the board is just unreachable, you can correct its address there, or continue without it.

**From a shell** (needs `openssl` and `curl`):

1. Press **BOOT** on the board. For 2 minutes it shows a one-time code such as `7KQ2-M9XA-3FPD-W4HN`.
2. On the new device, run:
   ```bash
   esp32/pki.sh pair desktop        # asks for the board's IP and the code
   #   now press BOOT on the board to approve 'desktop'
   ```
3. The OLED asks `pair new device? desktop`. Press **BOOT** again.
   ```
   #   ✓ paired as 'desktop'; start the app and unlock with your master password
   ```

The device makes its own key, and only a certificate request leaves it. Both sides authenticate the exchange with the code, bound to the board's certificate, so someone on your Wi-Fi can't pair in between. A wrong code closes pairing (press BOOT again to retry). Pairing a name that already exists replaces its old certificate. Then start the app on the new machine: it finds the vault on the board and asks for your existing master password.
   The GUI title bar and the TUI show the sync status.

The board is a plain USB-powered device: plug it into any charger.

**Managing devices:** in the app, **Devices** (GUI title bar) or `d` (TUI) lists every paired device and when it last talked to the board, and revokes one: press BOOT on the board to confirm. From a shell, `./pki.sh devices` and `./pki.sh revoke <name>` do the same. No reflash needed. The confirmation stops a stolen device from revoking your others.

### PIN unlock

Settings → **Set PIN** (TUI: `k`) lets this computer unlock with a PIN of at least 4 digits instead of the master password. The board checks the PIN: this computer keeps the vault key locked with a secret that only the board holds and hands out only for the right PIN. After 5 wrong PINs the board deletes that secret, and the master password is needed again. So a copy of this computer's disk can't be used to guess the PIN offline. The PIN works only while the board is reachable; the master password always works. Each computer has its own PIN and its own count of wrong tries. Revoking or re-pairing a device removes its PIN.

### Using it away from home

**Don't port-forward the ESP32 to the internet.** Its TLS stack never gets security updates, and it's easy to knock offline. Instead, reach your home network over a VPN: a [Tailscale subnet router](https://tailscale.com/kb/1019/subnets) on any always-on home machine, or WireGuard on your router. The app config stays the same (use the board's LAN IP), and only your own devices can reach it.

## Configuration

Every front end (GUI and TUI) uses the same locations, whatever directory you start it from ([XDG](https://specifications.freedesktop.org/basedir-spec/latest/)):

```
~/.config/pwvault/            $XDG_CONFIG_HOME/pwvault
  config                      key=value settings (created with defaults on first run, mode 600)
  server.pem                  the board's pinned certificate    ┐
  device.pem, device.key      this device's certificate + key   ┘ esp32/pki.sh pair <name>
~/.local/share/pwvault/       $XDG_DATA_HOME/pwvault
  vault.json, sync.json       local encrypted copy + sync cursors
```

Relative paths in `config` resolve against `~/.config/pwvault/`, and `~` is expanded. [`config.example`](config.example) is the template.

| Key | Default | Meaning |
|---|---|---|
| `espHost` | *(empty)* | ESP32 IP or name; empty = local only |
| `espPort` | `443` | |
| `localCopy` | `true` | `false` = device-only: the ESP32 is this machine's only store (see below) |
| `espCert` | `server.pem` | the board's pinned server certificate |
| `espClientCert`, `espClientKey` | `device.pem`, `device.key` | this device's certificate and private key |
| `dataPath` | *(empty)* = `~/.local/share/pwvault` | where `vault.json` and `sync.json` live |
| `defaultCipher` | `aes-256-gcm` | cipher preselected for new entries (`aes-256-gcm` or `chacha20-poly1305`) |
| `defaultUIMode` | `auto` | `gui`, `tui` or `auto` |
| `clipboardTimeoutSeconds`, `autoClipboardClear` | `30`, `true` | clipboard auto-clear |
| `showEncryptionInCredentials` | `true` | show each entry's cipher when viewing it |

### Local copy or device-only (per device)

| | `localCopy=true` (default) | `localCopy=false` (device-only) |
|---|---|---|
| Stored on this machine | encrypted copy in `~/.local/share/pwvault/` | nothing |
| Board off or out of reach | everything still works; syncs when back | no access until it's reachable |
| Each read | from the local copy (synced at most 30 s old) | fetched from the board, which shows it on the OLED |
| Good for | your own laptop and phone | a machine you trust less, or treating the ESP32 as a hardware key |

You can mix them: local-first on your laptop, device-only on a shared desktop. Everything else (certificate, master password) is the same.

## Development

```bash
nix-shell
make vault_test && ./vault_test          # crypto vectors, merge rule, multi-device sync, offline, conflicts
./build.sh --tests                       # also builds and runs base64_test and vault_test
./lint.sh --all                          # clang-format + clang-tidy + cppcheck
```

`vault_test` runs sync scenarios between simulated devices, with a local file standing in for the ESP32.

**`tests/fake_esp.py`** is a local stand-in for the board: the same API, mutual TLS, pairing, revocation and merge rule, with state kept in memory. Pairing is always open and every "BOOT press" is automatic. Use it to test clients (the desktop app, a future mobile app) without touching your real vault:
```bash
python3 tests/fake_esp.py --port 8443 --cert esp32/vault/cert.pem --key esp32/vault/key.pem --ca-dir /tmp/fake-ca --code ABCD0123EFGH4567
# pair a sandboxed client (its config: espHost=127.0.0.1, espPort=8443)
XDG_CONFIG_HOME=/tmp/dev PWVAULT_PAIR_PORT=8444 PWVAULT_CODE=ABCD0123EFGH4567 esp32/pki.sh pair test
PWVAULT_TEST_ESP="127.0.0.1:8443,/tmp/dev/pwvault/server.pem,/tmp/dev/pwvault/device.pem,/tmp/dev/pwvault/device.key" ./vault_test
``` To run it against a real board or the fake, set `PWVAULT_TEST_ESP="<host[:port]>,<server cert.pem>,<client .pem>,<client .key>"`. It always runs read-only checks: your certificate is accepted, a connection without one is refused, and an unreachable board counts as offline. The full sync round trip only runs on a board that doesn't hold a vault yet, and it leaves a test vault behind, so wipe the board's storage afterwards.

`tests/protocol_vectors.json` is a fixed reference, produced by an independent Python implementation, that the C++ code reproduces byte for byte. Any other client should reproduce it too. If you ever change the format on purpose, change `docs/PROTOCOL.md` first and add new vectors alongside the old ones.

### Android app

`android/` is a Kotlin + Compose app (Android 9+) that implements `docs/PROTOCOL.md` on its own: pair (§9, the key stays in the Android Keystore), unlock with the master password or a PIN, browse, copy, add, edit and delete entries, and sync with the board. It keeps a local copy, so it works away from home and syncs when it can reach the board again. Leaving the app locks it, screenshots are blocked, and copied values are cleared from the clipboard after 30 s.

```bash
cd android
nix-shell --run 'gradle testDebugUnitTest assembleDebug'   # JDK, Gradle and the Android SDK come from android/shell.nix
adb install build/outputs/apk/debug/pwvault-debug.apk
# also pair, sync and PIN against the fake board:
PWVAULT_TEST_PAIR="127.0.0.1:8443:8444,ABCD0123EFGH4567" nix-shell --run 'gradle testDebugUnitTest --rerun-tasks'
```

To pair from a laptop that's already paired, open **Devices → Add a device** in the desktop app (or `d`, then `a`, in the terminal UI): it shows a large QR code to scan with the phone, and you press BOOT on the board once to approve. Or, at the board, press BOOT: next to the code it shows a QR code. Tap **Scan the QR code** in the app, then press BOOT again to approve. Or type the board's IP address (`.local` names don't resolve reliably on Android) and the code instead. The scanner is Google's code scanner, which runs in Play services on the phone and needs no camera permission.

**Updates.** The app checks the GitHub releases once a day, and on **More → Check for updates**. When the latest release is newer and has a `pwvault.apk`, it offers to download it, and Android asks you to confirm the install. Android only installs an update signed with the same key as the installed app, so every release must be signed with your release key:

```bash
# once: make the key, keep it (and a backup) outside the repo; losing it means reinstalling every phone
keytool -genkeypair -keystore ~/.android/pwvault-release.jks -alias pwvault -keyalg EC -groupname secp256r1 -validity 10000 -dname CN=pwvault
# ~/.gradle/gradle.properties:
#   pwvaultKeystore=/home/<you>/.android/pwvault-release.jks
#   pwvaultKeystorePassword=...   pwvaultKeyAlias=pwvault   pwvaultKeyPassword=...

# each release: set versionName in android/build.gradle.kts to the tag without its v, then
cd android && nix-shell --run 'gradle assembleRelease'
cp build/outputs/apk/release/pwvault-release.apk pwvault.apk && gh release upload v2.1 pwvault.apk
```

A phone running a debug build (signed with the build machine's debug key) can't take these updates: install the first release build by hand after uninstalling the debug one, then pair again.

### Layout

```
docs/PROTOCOL.md        the contract: crypto format, ESP32 API, sync
src/vault/              client-side vault, no UI code
  Crypto.*                ICipher + AES-GCM / ChaCha20 (OpenSSL), PBKDF2, HMAC
  VaultFormat.*           meta, entry records, merge rule, key wrapping
  IVaultStore.h           store interface; LocalFileStore.*, EspStore.* (libcurl)
  Syncer.*                syncStores(): two-way sync between any two stores
  VaultService.*          the API the UIs use: unlock, get, put, remove, sync
src/core/UIManager.*    base class for front ends; talks only to VaultService
src/gui/, src/cli/      FLTK GUI and terminal UI
esp32/vault/            ESP32 firmware (store + OLED)
esp32/pki.sh            server cert; pair, list and revoke devices
android/                Android app (Kotlin): same protocol, own implementation
tests/                  vault_test.cpp, protocol vectors, fake_esp.py (stand-in board)
```

## License

MIT, see [LICENSE](LICENSE).
