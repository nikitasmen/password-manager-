# pwvault protocol, v1

This is the contract shared by every pwvault client (the desktop app, the Android app in `android/`) and every store (a local
file, the ESP32 board, `tests/fake_esp.py`). If the code and this document disagree, one of them is a bug. Change
this document first.

A client is correct when it reproduces `tests/protocol_vectors.json` byte for byte and follows the rules below.
Only clients encrypt and decrypt. Stores hold ciphertext and never see a key.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Conventions

- **Bytes in JSON:** keys, salts and AEAD blobs are standard base64 (RFC 4648 §4, with `=` padding). Ids,
  fingerprints, secrets, proofs and verifiers are lowercase hex.
- **JSON:** UTF-8. Readers MUST accept any valid JSON and MUST ignore unknown fields in records and replies. Writers
  SHOULD emit compact JSON (no whitespace). Exact bytes matter only for the entry plaintext in the test vectors (§4).
- **Time:** `updated` is milliseconds since the Unix epoch, as a signed 64-bit integer.
- **Strings as keys:** where a hex string is used as an HMAC key or message (§10, §11), the ASCII bytes of the hex
  text are used, not the decoded bytes.

## 2. Ciphers

Two AEAD ciphers are defined, each with a 32-byte key, a 12-byte nonce and a 16-byte tag:

| Wire name           | Algorithm                 |
|---------------------|---------------------------|
| `aes-256-gcm`       | AES-256-GCM               |
| `chacha20-poly1305` | ChaCha20-Poly1305 (RFC 8439) |

An **AEAD blob** is `base64(nonce || ciphertext || tag)`. The nonce MUST be fresh random bytes for every seal. A blob
shorter than 28 bytes after decoding, or whose tag doesn't verify, is a decryption failure.

Every blob is sealed with associated data (AAD) that binds it to its role. A blob moved to another role or id fails
to open.

| Blob                   | Key            | AAD (ASCII)                   |
|------------------------|----------------|-------------------------------|
| wrapped vault key (§3) | KEK            | `pwvault/v1/key`              |
| entry (§4)             | vault key      | `pwvault/v1/entry/<id>`       |
| PIN blob (§11)         | PIN wrap key   | `pwvault-pin:<vault_id>`      |

A record names its cipher in its `alg` field. A client MUST reject an `alg` it doesn't know rather than guess.

## 3. Vault meta and keys

```json
{"v":1,"vault_id":"<32 hex>","rev":1,"kdf":"pbkdf2-sha256","iter":600000,
 "salt":"<base64, 16 bytes>","alg":"aes-256-gcm","key":"<AEAD blob>"}
```

- `vault_id`: 16 random bytes, fixed for the vault's lifetime. Two stores with different `vault_id`s hold different
  vaults and MUST NOT be merged (§8).
- **KEK** = PBKDF2-HMAC-SHA256(master password as UTF-8, `salt`, `iter`, 32 bytes). `kdf` MUST be
  `pbkdf2-sha256`. New vaults use 600,000 iterations (the vectors use 1,000).
- **Vault key**: 32 random bytes, made once when the vault is created. `key` is the vault key sealed with the KEK
  under `alg`, with AAD `pwvault/v1/key`.
- **Password check:** there is no password hash. A password is right if and only if `key` opens.
- **Changing the master password** reseals the same vault key under a KEK from a fresh salt, keeps `vault_id`, and
  sets `rev` to `rev + 1`. Entries aren't touched.

## 4. Entries

```json
{"id":"<32 hex>","updated":1759075200000,"deleted":false,"alg":"aes-256-gcm","data":"<AEAD blob>","seq":7}
```

- **Id** = first 16 bytes of HMAC-SHA256(vault key, lowercase platform), in hex. Lowercasing maps ASCII `A`-`Z` to
  `a`-`z` byte by byte and leaves every other byte alone (no Unicode case folding). So one platform gets the same id
  on every device, and a store can't read platform names from ids.
- **Plaintext** is the JSON object `{"platform":…,"username":…,"password":…}`, all three non-empty strings. The
  vectors expect exactly this key order, compact, with non-ASCII emitted as raw UTF-8.
- `data` is the plaintext sealed with the vault key under `alg`, with AAD `pwvault/v1/entry/<id>`.
- **Tombstone** (a delete): `deleted: true`, `data: ""`, `alg: "aes-256-gcm"`. It is kept forever, so the delete
  propagates.
- `seq` belongs to the store holding the record (§6). A store MUST ignore the `seq` of a record it receives and
  assign its own.
- **Size:** a record's JSON SHOULD stay under 12 KB, so it fits in one ESP32 request (§7). Clients refuse larger
  entries up front, since such a record would block sync forever.
- **Timestamps:** a client writing an entry sets `updated = max(now, updated of the version it has + 1)`. An edit
  therefore always beats the version it replaces, even if this device's clock is behind (see §12).

**Known limit of v1:** the id depends only on the platform, so a vault holds one account per platform. Adding a
second account for the same platform overwrites the first. Changing this means a new id derivation, which is a v2
format with its own vectors.

## 5. Merge rule

A store holding record `cur` accepts an incoming record `in` for the same id only if `in` is newer:

```
in.updated > cur.updated, or
in.updated == cur.updated and in.data > cur.data   (bytewise, as unsigned bytes)
```

A record for an id the store doesn't have is always accepted. The rule is deterministic, so every store converges on
the same winner. Receiving the same record twice changes nothing, since it isn't newer. A tombstone's empty `data`
loses ties against any live record with the same `updated`.

## 6. Stores

A store holds one meta and a set of entry records, and offers four operations:

| Operation              | Semantics |
|------------------------|-----------|
| `getMeta()`            | The meta, or none if there is no vault yet. |
| `putMeta(meta, ifRev)` | Compare-and-swap: writes only if the current `rev` equals `ifRev` (0 = no meta yet). Returns false on conflict. |
| `changesAfter(seq)`    | Every record whose `seq` > `seq`, plus the store's current `seq`. |
| `putEntries(records)`  | Applies §5 to each record. Each accepted record gets `seq = ++store.seq`. |

`seq` is a per-store counter. It increases with every accepted write and is never reused (a crash may leave a gap).
It orders changes within one store only.

**Local file** (`vault.json`, in the data directory): `{"seq":N,"meta":{…},"entries":{"<id>":{record}}}`. Writes
take an exclusive lock on `vault.json.lock` and replace the file atomically (temp file + rename).

**ESP32:** the HTTP API in §7. `tests/fake_esp.py` implements the same API in memory.

## 7. ESP32 HTTP API

**Transport:** HTTPS on port 443 with mutual TLS.

- The server cert has the name `pwvault.local` (made by `esp32/pki.sh server`). Clients pin that exact cert and
  verify the name `pwvault.local` even when they connect by IP.
- Clients present a cert issued by the board's device CA (§10). The handshake refuses anything else.
- Clients SHOULD keep one connection open: a handshake costs about 0.5 s, a reused request about 0.06 s.

**Authorization:** the device name is the client cert's CN. A request is authorized only if `/devices.json` maps that
name to the SHA-256 of exactly that cert. A revoked or replaced cert gets `403 {"error":"device revoked"}`, and the
board closes the connection.

Request and reply bodies are JSON. Errors are `{"error":"<message>"}`. A request body is at most 16 KB (413 otherwise).

| Request | Body | Replies |
|---|---|---|
| `GET /meta` | | 200 meta (verbatim, as last stored); 404 no vault yet |
| `PUT /meta` | `{"meta":{…},"if_rev":N}` | 200 `{"ok":true}`; 409 `rev` isn't `if_rev`; 400 malformed |
| `GET /entries?after=N` | | 200 `{"entries":[…],"seq":S}`: records with `seq` > N, in no particular order |
| `POST /entries` | `{"entries":[…]}`, at most 32 | 200 `{"seq":S}`; 400 if any record is malformed (then none is written) |
| `POST /access` | `{"platform":…,"username":…}` | 200. Display-only hint for the OLED (see §12) |
| `GET /devices` | | 200 `{"devices":[{"name":…,"seen":T}],"you":"<name>","storage":{"used":B,"total":B,"records":N}}`: `storage` is the board's flash for the vault, in bytes, and how many entry records it holds (tombstones included). Optional: older firmware omits it |
| `DELETE /devices/<name>` | | 202 `{"pending":true}`; 404 no such device (§10) |
| `POST /pair/open` | | 200 `{"code":…,"qr":…,"seconds":S}`: opens pairing like a BOOT press, or returns the open session's code (§9) |
| `PUT /pin` | `{"verifier":"<64 hex>"}` | 200 `{"secret":"<64 hex>"}` (§11) |
| `POST /pin` | `{"proof":"<64 hex>"}` | 200 `{"secret":…}`; 403 `{"error":…,"left":K}`; 410 PIN removed; 404 no PIN (§11) |

- **`POST /entries` validation:** `id` is exactly 32 lowercase hex characters (it becomes a file name). `updated` is
  an integer, `deleted` a boolean, and `alg` and `data` are strings. Each record is merged with §5; rejected ones
  are skipped silently.
- **`seen`** is the Unix time of the device's last request since the board booted, or 0 if unknown.

## 8. Sync

`syncStores(local, remote)` syncs two stores. It is safe to repeat, and it keeps its cursors in `sync.json` next to
the local vault: `{"vault_id":…,"local_seq":L,"remote_seq":R}`. A missing or corrupt cursor file means "sync
everything", which §5 makes harmless.

1. **Meta.** If neither side has one, stop. If both do and their `vault_id`s differ, fail with *vault mismatch* and
   never merge. Otherwise the winner is the meta with the higher `rev`, with ties broken by the larger `key` blob
   (bytewise). The winner is copied to the other side with `putMeta(winner, loser.rev or 0)`. A lost CAS race is
   left to the next sync.
2. **Reset the cursors to 0** when:
   - the cursors belong to another `vault_id`,
   - either side had no meta before this sync (a new or wiped store has none of the other side's history), or
   - either store's current `seq` is below its cursor (its history restarted, e.g. a restored backup).
3. **Read both sides:** `theirs = remote.changesAfter(R)`, then `mine = local.changesAfter(L)`.
4. **Push** `mine` to the remote, in batches of at most 32 records and 12 KB.
5. **Pull:** `local.putEntries(theirs)`.
6. **Save** `remote_seq = theirs.seq` and `local_seq = mine.seq`. Both are read in step 3, before any write. Using
   the post-pull local `seq` could skip a write another app instance made meanwhile. The cost is that records get
   echoed back once in each direction, and §5 ignores them.

An unreachable remote is *offline*: normal, not an error. The client keeps working on the local store and syncs
later.

**When the desktop app syncs:** on unlock, after every write, and before a read once the last sync attempt is
older than 30 s.

**Device-only mode** (`localCopy=false`): the board is the only store. No sync runs, and every read goes to the
board.

## 9. Pairing

Pairing issues a new device's certificate. It runs on a second TLS server, port 8444, with no client cert, which is
open only while pairing mode is on.

1. A BOOT press on the board opens pairing for 2 minutes and shows a 16-character code. A paired device can also
   open it with `POST /pair/open`, which returns the code, the QR text (below) and the seconds left, so a laptop can
   show a large QR for a phone to scan. The OLED then names the device that opened it. The approving press in step 4
   is still required, so a paired device alone can't add another. Each character is from
   Crockford base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), 80 bits in total. Clients normalize what the user types:
   they drop spaces and dashes, uppercase, and read `I` and `L` as `1` and `O` as `0`.
   The board also shows a QR code of `PWVAULT:<its IPv4 address>:<code>` (all QR alphanumeric characters), so a
   phone can scan the address and code instead of typing them. The QR is only a convenience: it carries nothing the
   OLED text doesn't, and the macs below still authenticate the exchange.
2. The client connects without verifying, and takes `fp` = hex SHA-256 of the server cert's DER. It makes a P-256
   key and a CSR with `CN=<name>`. A name is 1-20 characters of `a-z 0-9 -` and doesn't start with `-`.
3. `POST /pair` with `{"name":…,"csr":"<base64 DER>","mac":…}`, where
   `mac = hex HMAC-SHA256(code, "pwvault-pair-req\n" + fp + "\n" + name + "\n" + csr)`. The client pins the cert it
   just fingerprinted for this request.
4. The board checks the mac in constant time. A wrong mac (403) closes pairing. It then asks for a second BOOT press
   (up to 60 s) and signs the CSR: validity 2025-2049, key usage digitalSignature, extended key usage clientAuth.
5. Reply 200 `{"cert":"<base64 DER>","mac":…}`, where `mac = hex HMAC-SHA256(code, "pwvault-pair-resp\n" + fp + "\n" +
   cert)`. The client MUST check this mac, and that the cert's public key is its own, before saving anything. It then
   saves the server cert as its pinned `server.pem`.

A man-in-the-middle presents a different cert, which changes `fp`. It can't produce valid macs without the code,
and the code can't be brute-forced offline from one exchange.

A pairing session handles one request, right or wrong. Pairing a name that already exists replaces its fingerprint,
so the old cert stops working, and deletes that name's PIN record (§11).

## 10. Devices and revocation

- **Device CA:** the board makes a P-256 CA on first boot (`/ca.key`, `/ca.pem`). The CA key never leaves the board.
- **Device list:** `/devices.json` maps each paired name to the hex SHA-256 of its one valid cert. A name missing from
  it is revoked.
- **Revocation takes a press.** `DELETE /devices/<name>` only records a pending request (202), which lasts 60 s. A
  newer request replaces it. The OLED shows the name and who asked, and a BOOT press performs it, so a stolen device
  can't lock out the others. Revoking removes the name and its PIN record. Clients poll `GET /devices` until the
  name is gone.

## 11. PIN unlock

A PIN unlocks a vault on one device, with the board's help. The master password stays the real key.

**Setting a PIN** (the vault must be unlocked, and the user re-enters the master password):

1. The client picks a 16-byte `salt`. PIN = 4-32 ASCII digits.
2. `proof = hex(PBKDF2-HMAC-SHA256(PIN, salt, 600000, 32 bytes))`.
3. `PUT /pin {"verifier": hex SHA-256(proof)}`. The board stores `/pin/<name>` =
   `{"secret":<64 hex, random>,"verifier":…,"fails":0}` and returns the secret.
4. `wrapKey = HMAC-SHA256(secret, "pwvault-pin-key\n" + proof)`, 32 bytes.
5. The client seals the raw vault key with AES-256-GCM under `wrapKey`, AAD `pwvault-pin:<vault_id>`. It saves
   `pin.json` = `{"salt":…,"iter":600000,"blob":…}` in its config directory, mode 600.

**Unlocking:** the client recomputes `proof` and sends `POST /pin {"proof"}`.

- If `SHA-256(proof)` matches the verifier, the board resets `fails` and returns the secret. The client derives
  `wrapKey` and opens the blob.
- A wrong proof increments `fails` in flash before the board replies: 403 with `left`. The 5th wrong proof deletes the
  record (410). If the count can't be written, the record is deleted too, so no guess goes uncounted.
- 404 or 410 means the PIN is gone. The client deletes `pin.json` and falls back to the master password.

`pin.json` alone can't be brute-forced: every guess needs the board's secret, and the board allows 5.

**Client-local unlock.** A client MAY also keep the vault key sealed under a key its platform guards, as long as the
master password stays the real key and nothing new goes over the wire. The Android app's fingerprint unlock is one:
`bio.json` = `{"vault_id":…,"iv":…,"blob":…}`, the vault key sealed with AES-256-GCM (AAD `pwvault-bio:<vault_id>`)
under an Android Keystore key that works only right after a strong biometric match and is destroyed when a
fingerprint is added to the phone. It works without the board.

## 12. Assumptions and threat model

**Clocks.** §5 is last-writer-wins on `updated`, which comes from the writing device's clock. The §4 timestamp rule
makes an edit beat the version it was made from, so sequential edits are safe whatever the clocks say. For
*concurrent* edits of the same entry (two devices edit it before either syncs), the device whose clock reads later
wins, and the other edit is lost without a warning. Clients assume clocks roughly right, which NTP provides. A clock
far in the future makes that device's concurrent edits win until real time catches up.

**What each attacker gets:**

| Attacker | Gets |
|---|---|
| Someone on your network | Nothing: mutual TLS with a pinned server cert. |
| A device without a cert from the device CA | Nothing: the handshake is refused. |
| A revoked device | One 403, then the connection is closed. |
| One of your devices, without the master password | Ciphertext. With a PIN set, 5 tries at the PIN, then the PIN is deleted. |
| The board alone | Ciphertext, which needs an offline brute force of the master password at 600,000 PBKDF2 rounds per guess. It also gets the CA key (it can issue certs for itself) and every device's PIN `secret`. |
| A phone with fingerprint unlock, without your finger | Nothing more than without it: the key never leaves the phone's secure hardware, which needs a strong biometric match for every use, and adding a fingerprint destroys it. |
| The board **and** a device with a PIN set | **The vault key, if the PIN is weak.** With the `secret` from the board's flash and `pin.json`, the PIN can be brute-forced offline without the board's try limit: each guess costs 600,000 PBKDF2 rounds, and a 4-digit PIN has 10,000 candidates. |

**Why board plus device breaks the PIN:** the board's LittleFS isn't encrypted, so `/pin/<name>` is readable from
flash by anyone holding the board. Two things would close this gap. ESP32 flash encryption (it burns eFuses and
can't be undone) would keep the flash contents secret. A secure element would keep the secret out of readable storage
altogether. Neither is used. If both a board and a device with a PIN can be stolen together, use a long PIN or no PIN.

**Metadata the board sees:**

- Entry ids hide platform names, but `POST /access` sends the platform and username of every entry read, in the
  clear, as a hint for the OLED. The board (and anything attached to its USB serial port) learns which accounts are read,
  when, and by which device.
- The board also sees the number of entries, their sizes, and when each one changes.

**Out of scope:** malware on an unlocked device, and a compromised build or update channel for a client.
