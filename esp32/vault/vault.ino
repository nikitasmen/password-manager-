// ESP32 vault store: docs/PROTOCOL.md §6-7. Zero-knowledge: it stores ciphertext records and never sees a key.
// Mutual TLS: the board is its own device CA. Only certificates it issued, and hasn't revoked, get in.
// The OLED shows CPU, RAM and flash use, and which device read which entry (from the client's display hint).
//
// Pairing (esp32/pki.sh pair): press BOOT and the board opens PAIR_PORT for PAIR_MS, showing a one-time code.
// The new device sends {name, csr, mac}, mac = HMAC-SHA256(code, "pwvault-pair-req\n" fp "\n" name "\n" csr), fp being
// the hex SHA-256 of the server cert it saw; a MITM's cert changes fp, and the code has 80 bits, so it can't be
// forged or brute-forced offline. A wrong mac closes pairing. A second BOOT press approves; the reply is
// {cert, mac = HMAC(code, "pwvault-pair-resp\n" fp "\n" cert)}. csr/cert are base64 DER.
//
// LittleFS layout: /meta.json     vault meta, verbatim
//                  /seq           store sequence counter
//                  /e/<id>        one entry record (JSON) per file
//                  /ca.key, /ca.pem  device CA, made on first boot
//                  /server.key, /server.pem  TLS server cert for pwvault.local, made on first boot
//                  /devices.json  {name: hex SHA-256 of its current cert}; a name not in it is revoked
//                  /pin/<name>    PIN unlock for that device: {secret, verifier, fails}
//
// PIN unlock (/pin): the client keeps the vault key wrapped with HMAC(secret, proof), proof being a slow hash of the
// PIN; the board holds `secret` and releases it only for the right proof (verifier = SHA-256 of the proof's hex).
// PIN_TRIES wrong proofs delete the record, and so does a wrong one the board fails to count: no free guesses.
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ArduinoJson.h>
#include <DNSServer.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <WebServer.h>
#include <WiFi.h>
#include <Wire.h>
#include <esp_https_server.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <esp_tls.h>
#include <esp_random.h>
#include <esp_wifi.h>
#include <mbedtls/base64.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <qrcode.h>  // espressif__qrcode, bundled with the core

#include <atomic>
#include <mutex>
#include <vector>

#if __has_include("cert.h")
#include "cert.h"  // legacy server cert from `pki.sh server`: copied to flash once, so paired devices stay paired
#endif

// Hardware: found by I2C scan on this board
constexpr int OLED_SDA = 21, OLED_SCL = 22, OLED_ADDR = 0x3C, OLED_W = 128, OLED_H = 64;
constexpr int BUTTON = 0;  // BOOT, active low

constexpr const char* HOSTNAME = "pwvault";  // pwvault.local, must match the cert
constexpr uint32_t EVENT_SHOW_MS = 8000;
constexpr size_t MAX_BODY = 16 * 1024;
constexpr size_t MAX_BATCH = 32;
constexpr uint16_t PAIR_PORT = 8444;
constexpr uint32_t PAIR_MS = 120000, CONFIRM_MS = 60000;
constexpr int PIN_TRIES = 5;
constexpr const char* SETUP_SSID = "pwvault-ap";  // the Wi-Fi setup hotspot
constexpr uint32_t WIFI_WAIT_MS = 30000;          // at boot, before falling back to setup

Adafruit_SSD1306 oled(OLED_W, OLED_H, &Wire, -1);
std::mutex mtx;  // guards storage and `event`; http handlers and loop() run on different tasks
uint64_t seq = 0;
// id -> seq for every stored record, so incremental reads open only changed files (~40 B per entry).
struct IndexEntry {
    char id[33];
    uint64_t seq;
};
std::vector<IndexEntry> seqIndex;
struct {
    String who, line1, line2, note;
    uint32_t until = 0;
} event;
// Paired devices, name -> fingerprint of the one cert that may use that name. Guarded by mtx.
struct Device {
    String name, fp;
    time_t seen = 0;  // last request, unix time (0 = not since boot, or no NTP yet); RAM only, spares the flash
};
std::vector<Device> devices;

void showEvent(const char* who, const String& line1, const String& line2, const String& note) {
    event = {who, line1, line2, note, millis() + EVENT_SHOW_MS};
    Serial.printf("[%s] %s | %s | %s\n", who, line1.c_str(), line2.c_str(), note.c_str());
}

// ---- storage ----

bool writeFile(const String& path, const String& content) {  // temp + rename: never half-written
    String tmp = path + ".tmp";
    File f = LittleFS.open(tmp, "w");
    if (!f) return false;
    bool ok = f.print(content) == content.length();
    f.close();
    return ok && LittleFS.rename(tmp, path);
}

String readFile(const String& path) {
    File f = LittleFS.open(path, "r");
    if (!f) return "";
    String s = f.readString();
    f.close();
    return s;
}

// Exactly `len` lowercase hex chars. Entry ids (32) become file names, so nothing else may pass.
bool validHex(const char* h, size_t len) {
    if (!h || strlen(h) != len) return false;
    for (const char* p = h; *p; p++)
        if (!isdigit(*p) && !(*p >= 'a' && *p <= 'f')) return false;
    return true;
}

// PROTOCOL.md §5: (updated, data) compared as (number, bytes)
bool isNewer(JsonObjectConst in, JsonObjectConst cur) {
    int64_t a = in["updated"], b = cur["updated"];
    if (a != b) return a > b;
    return strcmp(in["data"] | "", cur["data"] | "") > 0;
}

void indexPut(const char* id, uint64_t s) {
    for (IndexEntry& e : seqIndex)
        if (!strcmp(e.id, id)) return void(e.seq = s);
    IndexEntry e;
    strlcpy(e.id, id, sizeof e.id);
    e.seq = s;
    seqIndex.push_back(e);
}

void buildIndex() {
    File dir = LittleFS.open("/e");
    for (File f = dir.openNextFile(); f; f = dir.openNextFile()) {
        JsonDocument d;
        if (!deserializeJson(d, f) && validHex(f.name(), 32)) indexPut(f.name(), d["seq"].as<uint64_t>());
        f.close();
    }
    Serial.printf("indexed %u entries, seq %llu\n", (unsigned)seqIndex.size(), seq);
}

int currentRev() {
    JsonDocument m;
    String raw = readFile("/meta.json");
    return raw.length() && !deserializeJson(m, raw) ? m["rev"].as<int>() : 0;
}

// ---- crypto: device CA, fingerprints, HMAC ----

int rng(void*, unsigned char* out, size_t n) {
    esp_fill_random(out, n);  // hardware RNG; true random once Wi-Fi is up
    return 0;
}

String hex(const uint8_t* p, size_t n) {
    String s;
    char b[3];
    for (size_t i = 0; i < n; i++) s += (snprintf(b, sizeof b, "%02x", p[i]), b);
    return s;
}

String sha256Hex(const uint8_t* p, size_t n) {
    uint8_t h[32];
    mbedtls_sha256(p, n, h, 0);
    return hex(h, sizeof h);
}

String hmacHex(const String& key, const String& msg) {
    uint8_t h[32];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const uint8_t*)key.c_str(), key.length(),
                    (const uint8_t*)msg.c_str(), msg.length(), h);
    return hex(h, sizeof h);
}

bool sameMac(const String& a, const String& b) {  // constant time
    if (a.length() != b.length()) return false;
    uint8_t d = 0;
    for (size_t i = 0; i < a.length(); i++) d |= a[i] ^ b[i];
    return !d;
}

// 1-20 chars of a-z 0-9 -, first not '-': it is a cert CN and is shown on the OLED
bool validName(const char* n) {
    size_t len = n ? strlen(n) : 0;
    if (!len || len > 20 || n[0] == '-') return false;
    for (const char* p = n; *p; p++)
        if (!isdigit(*p) && !(*p >= 'a' && *p <= 'z') && *p != '-') return false;
    return true;
}

mbedtls_pk_context caKey;
String caPem;          // handed to the https server, which verifies client certs against it
String serverFp;       // SHA-256 of our server cert (DER), bound into the pairing macs
const char* CA_NAME = "CN=pwvault device CA";

// Signs `subject` (a public key) as `cn`; CA cert when ca=true (then subject is caKey). DER, or "" on failure.
String issueCert(mbedtls_pk_context* subject, const String& cn, bool ca) {
    mbedtls_x509write_cert c;
    mbedtls_x509write_crt_init(&c);
    uint8_t serial[16];
    rng(nullptr, serial, sizeof serial);
    serial[0] &= 0x7f;  // positive
    mbedtls_asn1_sequence eku = {};
    eku.buf.tag = MBEDTLS_ASN1_OID;
    eku.buf.p = (unsigned char*)MBEDTLS_OID_CLIENT_AUTH;
    eku.buf.len = MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH);
    mbedtls_x509write_crt_set_version(&c, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&c, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&c, subject);
    mbedtls_x509write_crt_set_issuer_key(&c, &caKey);
    std::vector<uint8_t> buf(1024);
    int n = -1;
    if (!mbedtls_x509write_crt_set_subject_name(&c, ca ? CA_NAME : ("CN=" + cn).c_str()) &&
        !mbedtls_x509write_crt_set_issuer_name(&c, CA_NAME) &&
        !mbedtls_x509write_crt_set_serial_raw(&c, serial, sizeof serial) &&
        !mbedtls_x509write_crt_set_validity(&c, "20250101000000", "20491231235959") &&
        !mbedtls_x509write_crt_set_basic_constraints(&c, ca, ca ? 0 : -1) &&
        !mbedtls_x509write_crt_set_key_usage(&c, ca ? MBEDTLS_X509_KU_KEY_CERT_SIGN : MBEDTLS_X509_KU_DIGITAL_SIGNATURE) &&
        (ca || !mbedtls_x509write_crt_set_ext_key_usage(&c, &eku)))
        n = mbedtls_x509write_crt_der(&c, buf.data(), buf.size(), rng, nullptr);  // written at the END of buf
    mbedtls_x509write_crt_free(&c);
    return n > 0 ? String((const char*)buf.data() + buf.size() - n, n) : String();
}

// Loads the CA from flash, or makes one on first boot. Needs Wi-Fi up (entropy).
bool loadCa() {
    mbedtls_pk_init(&caKey);
    String key = readFile("/ca.key");
    caPem = readFile("/ca.pem");
    if (key.length() && caPem.length())
        return !mbedtls_pk_parse_key(&caKey, (const uint8_t*)key.c_str(), key.length() + 1, nullptr, 0, rng, nullptr);
    Serial.println("creating device CA");
    std::vector<uint8_t> pem(512);
    if (mbedtls_pk_setup(&caKey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) ||
        mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(caKey), rng, nullptr) ||
        mbedtls_pk_write_key_pem(&caKey, pem.data(), pem.size()))
        return false;
    String der = issueCert(&caKey, "", true);
    std::vector<uint8_t> out(1024);
    size_t n = 0;
    if (!der.length() || mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
                                                  (const uint8_t*)der.c_str(), der.length(), out.data(), out.size(), &n))
        return false;
    caPem = (const char*)out.data();
    // cert last: a crash in between leaves no /ca.pem, so the next boot starts over
    return writeFile("/ca.key", (const char*)pem.data()) && writeFile("/ca.pem", caPem);
}

String serverCertPem, serverKeyPem;  // the TLS servers' cert and key, from loadServerCert()

// Self-signed for pwvault.local (clients verify that name), like `openssl req -x509`. Clients don't need it
// beforehand: pairing hands it over, bound to the code by the macs.
bool makeServerCert() {
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    mbedtls_x509write_cert c;
    mbedtls_x509write_crt_init(&c);
    std::vector<uint8_t> keyPem(512), crtPem(1024);
    uint8_t serial[16];
    rng(nullptr, serial, sizeof serial);
    serial[0] &= 0x7f;  // positive
    mbedtls_x509_san_list san = {};
    san.node.type = MBEDTLS_X509_SAN_DNS_NAME;
    san.node.san.unstructured_name.p = (unsigned char*)"pwvault.local";
    san.node.san.unstructured_name.len = strlen("pwvault.local");
    bool ok = !mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) &&
              !mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), rng, nullptr) &&
              !mbedtls_pk_write_key_pem(&key, keyPem.data(), keyPem.size());
    if (ok) {
        mbedtls_x509write_crt_set_version(&c, MBEDTLS_X509_CRT_VERSION_3);
        mbedtls_x509write_crt_set_md_alg(&c, MBEDTLS_MD_SHA256);
        mbedtls_x509write_crt_set_subject_key(&c, &key);
        mbedtls_x509write_crt_set_issuer_key(&c, &key);
        ok = !mbedtls_x509write_crt_set_subject_name(&c, "CN=pwvault.local") &&
             !mbedtls_x509write_crt_set_issuer_name(&c, "CN=pwvault.local") &&
             !mbedtls_x509write_crt_set_serial_raw(&c, serial, sizeof serial) &&
             !mbedtls_x509write_crt_set_validity(&c, "20250101000000", "20491231235959") &&
             !mbedtls_x509write_crt_set_basic_constraints(&c, 1, -1) &&
             !mbedtls_x509write_crt_set_subject_alternative_name(&c, &san) &&
             !mbedtls_x509write_crt_pem(&c, crtPem.data(), crtPem.size(), rng, nullptr);
    }
    mbedtls_x509write_crt_free(&c);
    mbedtls_pk_free(&key);
    if (!ok) return false;
    serverKeyPem = (const char*)keyPem.data();
    serverCertPem = (const char*)crtPem.data();
    return true;
}

// Loads the server cert from flash, or makes one on first boot (after Wi-Fi: entropy). Sets serverFp.
bool loadServerCert() {
    serverKeyPem = readFile("/server.key");
    serverCertPem = readFile("/server.pem");
    if (!serverKeyPem.length() || !serverCertPem.length()) {
#if __has_include("cert.h")
        serverKeyPem = KEY_PEM;
        serverCertPem = CERT_PEM;
#else
        Serial.println("creating server cert");
        if (!makeServerCert()) return false;
#endif
        // cert last: a crash in between leaves no /server.pem, so the next boot starts over
        if (!writeFile("/server.key", serverKeyPem) || !writeFile("/server.pem", serverCertPem)) return false;
    }
    mbedtls_x509_crt own;
    mbedtls_x509_crt_init(&own);
    bool ok = !mbedtls_x509_crt_parse(&own, (const uint8_t*)serverCertPem.c_str(), serverCertPem.length() + 1);
    if (ok) serverFp = sha256Hex(own.raw.p, own.raw.len);
    mbedtls_x509_crt_free(&own);
    return ok;
}

void loadDevices() {
    JsonDocument d;
    if (deserializeJson(d, readFile("/devices.json"))) return;
    for (JsonPair kv : d.as<JsonObject>()) devices.push_back({kv.key().c_str(), kv.value().as<String>(), 0});
}

bool saveDevices() {
    JsonDocument d;
    for (const Device& dv : devices) d[dv.name] = dv.fp;
    String out;
    serializeJson(d, out);
    return writeFile("/devices.json", out);
}

Device* findDevice(const String& name) {
    for (Device& d : devices)
        if (d.name == name) return &d;
    return nullptr;
}

// ---- BOOT button: pairing mode and confirmations ----

std::atomic<bool> pressed{false};  // set by the ISR, consumed by loop()
enum Ask { ASK_NONE, ASK_WAITING, ASK_YES };
std::atomic<int> ask{ASK_NONE};  // a handler waiting for a press to approve something
struct {
    String line1, line2;
} prompt;  // guarded by mtx

void IRAM_ATTR onButton() {
    static uint32_t last = 0;
    uint32_t now = millis();
    if (now - last > 300) pressed = true;  // debounce
    last = now;
}

// Shows a question and waits up to `ms` for a BOOT press. Call without holding mtx.
bool confirm(const String& line1, const String& line2, uint32_t ms) {
    int none = ASK_NONE;
    if (!ask.compare_exchange_strong(none, ASK_WAITING)) return false;  // someone else is asking
    {
        std::lock_guard<std::mutex> g(mtx);
        prompt = {line1, line2};
    }
    for (uint32_t t = millis(); ask != ASK_YES && millis() - t < ms;) delay(50);
    bool yes = ask == ASK_YES;
    std::lock_guard<std::mutex> g(mtx);
    prompt = {};
    ask = ASK_NONE;
    return yes;
}

// ---- http helpers ----

// The handshake already rejected anyone without a certificate from our CA. When a session opens we remember its
// cert's CN (the device name shown on the OLED) and fingerprint by socket; requests look them up.
// Only touched from the main httpd task (session callback + handlers), so no lock needed.
struct Session {
    int fd = -1;
    char name[24] = "";
    char fp[65] = "";
} sessions[8];  // > max_open_sockets

void onSession(esp_https_server_user_cb_arg_t* arg) {
    int fd = -1;
    if (esp_tls_get_conn_sockfd(arg->tls, &fd) != ESP_OK) return;
    for (Session& s : sessions)
        if (s.fd == fd) s.fd = -1;  // closed, or a stale entry for a reused fd
    if (arg->user_cb_state != HTTPD_SSL_USER_CB_SESS_CREATE) return;
    auto* ssl = static_cast<mbedtls_ssl_context*>(esp_tls_get_ssl_context(arg->tls));
    const mbedtls_x509_crt* crt = ssl ? mbedtls_ssl_get_peer_cert(ssl) : nullptr;
    char dn[96];
    if (!crt || mbedtls_x509_dn_gets(dn, sizeof dn, &crt->subject) < 0) return;
    const char* cn = strstr(dn, "CN=");
    if (!cn) return;
    for (Session& s : sessions) {
        if (s.fd != -1) continue;
        s.fd = fd;
        strlcpy(s.name, cn + 3, sizeof s.name);
        if (char* comma = strchr(s.name, ',')) *comma = 0;
        strlcpy(s.fp, sha256Hex(crt->raw.p, crt->raw.len).c_str(), sizeof s.fp);
        return;
    }
}

// Device name for this request, or nullptr if its cert isn't the current one for that name (revoked, replaced).
// Call with mtx held.
const char* authDevice(httpd_req_t* r) {
    int fd = httpd_req_to_sockfd(r);
    for (const Session& s : sessions) {
        if (s.fd != fd) continue;
        Device* d = findDevice(s.name);
        if (!d || d->fp != s.fp) return nullptr;
        time_t now = time(nullptr);
        d->seen = now > 1700000000 ? now : 0;  // before NTP, time() counts from boot
        return s.name;
    }
    return nullptr;
}

esp_err_t sendJson(httpd_req_t* r, const char* status, const String& body) {
    httpd_resp_set_status(r, status);
    httpd_resp_set_type(r, "application/json");
    return httpd_resp_send(r, body.c_str(), body.length());
}

esp_err_t fail(httpd_req_t* r, const char* status, const char* msg) {
    return sendJson(r, status, String("{\"error\":\"") + msg + "\"}");
}

// For revoked devices: answer once, then close the connection so it can't keep sending requests.
esp_err_t forbid(httpd_req_t* r) {
    fail(r, "403 Forbidden", "device revoked");
    httpd_sess_trigger_close(r->handle, httpd_req_to_sockfd(r));
    return ESP_OK;
}

esp_err_t ok(httpd_req_t* r) {
    return sendJson(r, "200 OK", "{\"ok\":true}");
}

// Returns false and replies with the error itself on failure.
bool readJson(httpd_req_t* r, JsonDocument& doc) {
    size_t n = r->content_len;
    if (n > MAX_BODY) return fail(r, "413 Payload Too Large", "body too large"), false;
    std::vector<char> body(n);
    for (size_t got = 0; got < n;) {
        int k = httpd_req_recv(r, &body[got], n - got);
        if (k <= 0) return fail(r, "400 Bad Request", "short body"), false;
        got += k;
    }
    if (deserializeJson(doc, (const char*)body.data(), n)) return fail(r, "400 Bad Request", "bad json"), false;
    return true;
}

// Returns nullptr and replies with the error itself on failure.
const char* readBody(httpd_req_t* r, JsonDocument& doc) {
    const char* who = authDevice(r);
    if (!who) return forbid(r), nullptr;
    return readJson(r, doc) ? who : nullptr;
}

// ---- handlers (each holds mtx for its whole run) ----

esp_err_t hGetMeta(httpd_req_t* r) {
    std::lock_guard<std::mutex> g(mtx);
    if (!authDevice(r)) return forbid(r);
    String meta = readFile("/meta.json");
    return meta.length() ? sendJson(r, "200 OK", meta) : fail(r, "404 Not Found", "no vault yet");
}

esp_err_t hPutMeta(httpd_req_t* r) {
    std::lock_guard<std::mutex> g(mtx);
    JsonDocument in;
    const char* who = readBody(r, in);
    if (!who) return ESP_OK;
    JsonObject meta = in["meta"];
    if (meta.isNull() || !in["if_rev"].is<int>() || !meta["rev"].is<int>() || !meta["vault_id"].is<const char*>() ||
        !meta["key"].is<const char*>())
        return fail(r, "400 Bad Request", "need {meta, if_rev}");
    if (currentRev() != in["if_rev"].as<int>()) return fail(r, "409 Conflict", "rev changed");
    String out;
    serializeJson(meta, out);
    if (!writeFile("/meta.json", out)) return fail(r, "500 Internal Server Error", "write failed");
    showEvent(who, "vault key updated", "rev " + String(meta["rev"].as<int>()), "saved");
    return ok(r);
}

esp_err_t hGetEntries(httpd_req_t* r) {
    std::lock_guard<std::mutex> g(mtx);
    if (!authDevice(r)) return forbid(r);
    char query[64], val[24];
    uint64_t after = 0;
    if (httpd_req_get_url_query_str(r, query, sizeof query) == ESP_OK &&
        httpd_query_key_value(query, "after", val, sizeof val) == ESP_OK)
        after = strtoull(val, nullptr, 10);

    // Streamed in ~3 KB chunks: RAM use doesn't grow with the vault, and few TLS records are sent.
    httpd_resp_set_type(r, "application/json");
    String buf = "{\"entries\":[";
    bool first = true;
    for (const IndexEntry& e : seqIndex) {
        if (e.seq <= after) continue;
        String rec = readFile(String("/e/") + e.id);
        if (!rec.length()) continue;
        if (!first) buf += ",";
        buf += rec;
        first = false;
        if (buf.length() > 3072) {
            httpd_resp_send_chunk(r, buf.c_str(), buf.length());
            buf = "";
        }
    }
    buf += "],\"seq\":" + String(seq) + "}";
    httpd_resp_send_chunk(r, buf.c_str(), buf.length());
    return httpd_resp_send_chunk(r, nullptr, 0);
}

esp_err_t hPostEntries(httpd_req_t* r) {
    std::lock_guard<std::mutex> g(mtx);
    JsonDocument in;
    const char* who = readBody(r, in);
    if (!who) return ESP_OK;
    JsonArray entries = in["entries"];
    if (entries.isNull() || entries.size() > MAX_BATCH) return fail(r, "400 Bad Request", "need {entries: [..32]}");
    for (JsonObject e : entries)  // validate the whole batch before writing any of it
        if (!validHex(e["id"], 32) || !e["updated"].is<int64_t>() || !e["deleted"].is<bool>() ||
            !e["alg"].is<const char*>() || !e["data"].is<const char*>())
            return fail(r, "400 Bad Request", "bad entry record");

    int accepted = 0;
    for (JsonObject e : entries) {
        String path = String("/e/") + e["id"].as<const char*>();
        JsonDocument cur;
        String raw = readFile(path);
        if (raw.length() && !deserializeJson(cur, raw) && !isNewer(e, cur.as<JsonObjectConst>())) continue;
        e["seq"] = ++seq;
        // /seq first: a crash after it only leaves a gap, never a reused seq
        if (!writeFile("/seq", String(seq))) return fail(r, "500 Internal Server Error", "write failed");
        String out;
        serializeJson(e, out);
        if (!writeFile(path, out)) return fail(r, "500 Internal Server Error", "write failed");
        indexPut(e["id"], seq);
        accepted++;
    }
    if (accepted) showEvent(who, "synced", String(accepted) + " change" + (accepted == 1 ? "" : "s"), "saved");
    return sendJson(r, "200 OK", "{\"seq\":" + String(seq) + "}");
}

esp_err_t hAccess(httpd_req_t* r) {
    JsonDocument in;
    const char* who;
    {
        std::lock_guard<std::mutex> g(mtx);
        who = readBody(r, in);
        if (!who) return ESP_OK;
        // ponytail: display-only and auto-approved; with a button, wait for a press here before replying
        showEvent(who, "wants: " + in["platform"].as<String>(), "user:  " + in["username"].as<String>(), "read");
    }
    return ok(r);
}


String b64(const String& der) {
    size_t n;
    std::vector<uint8_t> out(der.length() * 4 / 3 + 4);
    mbedtls_base64_encode(out.data(), out.size(), &n, (const uint8_t*)der.c_str(), der.length());
    return String((const char*)out.data(), n);
}

esp_err_t hDevices(httpd_req_t* r) {
    std::lock_guard<std::mutex> g(mtx);
    const char* who = authDevice(r);
    if (!who) return forbid(r);
    JsonDocument d;
    for (const Device& dv : devices) {
        JsonObject o = d["devices"].add<JsonObject>();
        o["name"] = dv.name;
        o["seen"] = (int64_t)dv.seen;
    }
    d["you"] = who;
    JsonObject st = d["storage"].to<JsonObject>();  // PROTOCOL.md §7: what the clients show as free space
    st["used"] = (uint64_t)LittleFS.usedBytes();
    st["total"] = (uint64_t)LittleFS.totalBytes();
    st["records"] = (uint64_t)seqIndex.size();
    String out;
    serializeJson(d, out);
    return sendJson(r, "200 OK", out);
}

// DELETE /devices/<name> only asks: the OLED shows the request and loop() revokes on a BOOT press, so a stolen
// device can't lock out the others, and a pending request doesn't hold up anyone's sync. A newer request replaces
// an older one; the screen names both the device and who asked, so press only for the right one.
struct {
    String name, by;
    uint32_t until = 0;
} pendingRevoke;  // guarded by mtx

bool revokePending() {
    return pendingRevoke.name.length() && (int32_t)(pendingRevoke.until - millis()) > 0;
}

void revokeNow() {  // mtx held
    const String name = pendingRevoke.name, by = pendingRevoke.by;
    pendingRevoke = {};
    for (size_t i = 0; i < devices.size(); i++)
        if (devices[i].name == name) devices.erase(devices.begin() + i);
    LittleFS.remove("/pin/" + name);
    showEvent(by.c_str(), "revoked", name, saveDevices() ? "saved" : "SAVE FAILED");
}

esp_err_t hRevoke(httpd_req_t* r) {
    std::lock_guard<std::mutex> g(mtx);
    const char* who = authDevice(r);
    if (!who) return forbid(r);
    String name = r->uri + strlen("/devices/");
    if (!findDevice(name)) return fail(r, "404 Not Found", "no such device");
    pendingRevoke = {name, who, millis() + CONFIRM_MS};
    return sendJson(r, "202 Accepted", "{\"pending\":true}");  // the client polls GET /devices
}

// ---- PIN unlock ----

// PUT /pin {verifier}: (re)sets this device's PIN; replies with the new secret
esp_err_t hSetPin(httpd_req_t* r) {
    std::lock_guard<std::mutex> g(mtx);
    JsonDocument in;
    const char* who = readBody(r, in);
    if (!who) return ESP_OK;
    if (!validHex(in["verifier"], 64)) return fail(r, "400 Bad Request", "need {verifier: 64 hex}");
    uint8_t raw[32];
    rng(nullptr, raw, sizeof raw);
    JsonDocument rec;
    rec["secret"] = hex(raw, sizeof raw);
    rec["verifier"] = in["verifier"];
    rec["fails"] = 0;
    String out;
    serializeJson(rec, out);
    if (!writeFile(String("/pin/") + who, out)) return fail(r, "500 Internal Server Error", "write failed");
    showEvent(who, "PIN set", "", "saved");
    return sendJson(r, "200 OK", "{\"secret\":\"" + rec["secret"].as<String>() + "\"}");
}

// POST /pin {proof}: the secret for the right proof; a wrong one counts, and the last allowed one deletes the PIN
esp_err_t hTryPin(httpd_req_t* r) {
    std::lock_guard<std::mutex> g(mtx);
    JsonDocument in, rec;
    const char* who = readBody(r, in);
    if (!who) return ESP_OK;
    if (!validHex(in["proof"], 64)) return fail(r, "400 Bad Request", "need {proof: 64 hex}");
    const String path = String("/pin/") + who;
    String raw = readFile(path);
    if (!raw.length() || deserializeJson(rec, raw)) return fail(r, "404 Not Found", "no PIN set");
    const char* proof = in["proof"];
    if (sameMac(sha256Hex((const uint8_t*)proof, strlen(proof)), rec["verifier"].as<String>())) {
        if (rec["fails"].as<int>()) {
            rec["fails"] = 0;
            String out;
            serializeJson(rec, out);
            writeFile(path, out);
        }
        showEvent(who, "unlocked", "with PIN", "");
        return sendJson(r, "200 OK", "{\"secret\":\"" + rec["secret"].as<String>() + "\"}");
    }
    int fails = rec["fails"].as<int>() + 1;
    // counted in flash before replying: cutting the power doesn't give extra tries
    if (fails >= PIN_TRIES) {
        LittleFS.remove(path);
        showEvent(who, "wrong PIN", "PIN removed", "use password");
        return sendJson(r, "410 Gone", "{\"error\":\"too many wrong PINs; the PIN was removed\",\"left\":0}");
    }
    rec["fails"] = fails;
    String out;
    serializeJson(rec, out);
    if (!writeFile(path, out)) {  // fail closed: an uncounted wrong try would be a free guess (e.g. flash filled up)
        LittleFS.remove(path);
        showEvent(who, "wrong PIN", "PIN removed", "use password");
        return sendJson(r, "410 Gone", "{\"error\":\"the board couldn't count the try; the PIN was removed\",\"left\":0}");
    }
    showEvent(who, "wrong PIN", String(PIN_TRIES - fails) + " tries left", "");
    return sendJson(r, "403 Forbidden", "{\"error\":\"wrong PIN\",\"left\":" + String(PIN_TRIES - fails) + "}");
}

// ---- pairing server (PAIR_PORT, no client cert, only while pairing mode is on) ----

httpd_handle_t pairServer = nullptr;
uint32_t pairUntil = 0;
String pairCode;                                    // the HMAC key: 16 chars, 80 bits
std::atomic<bool> pairBusy{false}, pairDone{false};  // loop() closes pairing once a request has been handled
std::atomic<bool> openAsked{false};                  // POST /pair/open wants pairing open
String openBy;                                       // ...and who asked (guarded by mtx)
String pairBy;                                       // the device that opened this session, "" for BOOT

esp_err_t hPair(httpd_req_t* r) {
    pairBusy = true;
    struct Done {
        ~Done() { pairDone = true, pairBusy = false; }  // one request per pairing session, right or wrong
    } done;
    JsonDocument in;
    if (!readJson(r, in)) return ESP_OK;
    String name = in["name"] | "", csr = in["csr"] | "", mac = in["mac"] | "";
    if (!sameMac(mac, hmacHex(pairCode, "pwvault-pair-req\n" + serverFp + "\n" + name + "\n" + csr))) {
        std::lock_guard<std::mutex> g(mtx);
        showEvent("pairing", "wrong code", "pairing closed", "");
        return fail(r, "403 Forbidden", "wrong code (or someone is intercepting)");
    }
    if (!validName(name.c_str())) return fail(r, "400 Bad Request", "name: 1-20 chars of a-z 0-9 -");

    std::vector<uint8_t> der(csr.length());
    size_t n = 0;
    mbedtls_x509_csr req;
    mbedtls_x509_csr_init(&req);
    struct Free {
        mbedtls_x509_csr* p;
        ~Free() { mbedtls_x509_csr_free(p); }
    } freeReq{&req};
    if (mbedtls_base64_decode(der.data(), der.size(), &n, (const uint8_t*)csr.c_str(), csr.length()) ||
        mbedtls_x509_csr_parse_der(&req, der.data(), n))
        return fail(r, "400 Bad Request", "bad csr");
    bool replacing;
    {
        std::lock_guard<std::mutex> g(mtx);
        replacing = findDevice(name);
    }
    if (!confirm(replacing ? "re-pair device?" : "pair new device?", name, CONFIRM_MS))
        return fail(r, "403 Forbidden", "not approved on the board");

    String cert = issueCert(&req.pk, name, false);
    if (!cert.length()) return fail(r, "500 Internal Server Error", "signing failed");
    {
        std::lock_guard<std::mutex> g(mtx);
        String fp = sha256Hex((const uint8_t*)cert.c_str(), cert.length());
        if (Device* d = findDevice(name)) d->fp = fp;  // the old cert stops working
        else devices.push_back({name, fp, 0});
        LittleFS.remove("/pin/" + name);  // a PIN belongs to the old pairing
        if (!saveDevices()) return fail(r, "500 Internal Server Error", "write failed");
        showEvent(name.c_str(), "paired", "", "welcome");
    }
    String certB64 = b64(cert);
    String mac2 = hmacHex(pairCode, "pwvault-pair-resp\n" + serverFp + "\n" + certB64);
    return sendJson(r, "200 OK", "{\"cert\":\"" + certB64 + "\",\"mac\":\"" + mac2 + "\"}");
}

void startPairing() {
    const char* ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";  // Crockford base32: no I L O U
    uint8_t raw[16];
    rng(nullptr, raw, sizeof raw);
    pairCode = "";
    for (uint8_t b : raw) pairCode += ALPHA[b & 31];
    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.servercert = (const uint8_t*)serverCertPem.c_str();
    conf.servercert_len = serverCertPem.length() + 1;  // PEM lengths include the NUL
    conf.prvtkey_pem = (const uint8_t*)serverKeyPem.c_str();
    conf.prvtkey_len = serverKeyPem.length() + 1;
    conf.port_secure = PAIR_PORT;
    conf.httpd.ctrl_port = ESP_HTTPD_DEF_CTRL_PORT + 2;  // the main server has +1
    conf.httpd.stack_size = 16384;
    conf.httpd.max_open_sockets = 2;
    if (httpd_ssl_start(&pairServer, &conf) != ESP_OK) {
        pairServer = nullptr;
        showEvent("pairing", "failed to start", "", "");
        return;
    }
    httpd_uri_t u = {};
    u.uri = "/pair";
    u.method = HTTP_POST;
    u.handler = hPair;
    httpd_register_uri_handler(pairServer, &u);
    pairDone = false;
    pairUntil = millis() + PAIR_MS;
}

void stopPairing() {
    httpd_ssl_stop(pairServer);
    pairServer = nullptr;
    pairCode = "";
    pairBy = "";
}

// POST /pair/open: a paired device opens pairing, as a BOOT press does, so it can show the code as a large QR.
// loop() does the opening (one place starts and stops the pairing server); this waits for it. Approving the new
// device still takes a press on the board, so a paired device alone can't add another.
esp_err_t hOpenPair(httpd_req_t* r) {
    {
        std::lock_guard<std::mutex> g(mtx);
        const char* who = authDevice(r);
        if (!who) return forbid(r);
        openBy = who;
    }
    openAsked = true;
    for (int i = 0; i < 60 && (openAsked || !pairServer); i++) delay(50);
    if (!pairServer) return fail(r, "503 Service Unavailable", "pairing didn't open");
    JsonDocument d;
    d["code"] = pairCode;
    d["qr"] = "PWVAULT:" + WiFi.localIP().toString() + ":" + pairCode;  // what the OLED's QR says (PROTOCOL.md §9)
    d["seconds"] = (int32_t)(pairUntil - millis()) / 1000;
    String out;
    serializeJson(d, out);
    return sendJson(r, "200 OK", out);
}

void startServer() {
    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.servercert = (const uint8_t*)serverCertPem.c_str();
    conf.servercert_len = serverCertPem.length() + 1;  // PEM lengths include the NUL
    conf.prvtkey_pem = (const uint8_t*)serverKeyPem.c_str();
    conf.prvtkey_len = serverKeyPem.length() + 1;
    conf.cacert_pem = (const uint8_t*)caPem.c_str();  // setting this makes a client certificate mandatory
    conf.cacert_len = caPem.length() + 1;
    conf.user_cb = onSession;
    conf.httpd.stack_size = 16384;       // TLS + JSON
    conf.httpd.lru_purge_enable = true;  // clients keep connections open; evict the idlest instead of refusing
    // Each TLS session holds ~40 KB (16 KB in + 16 KB out buffers in this core's mbedtls). The default 4 idle
    // sessions don't fit in RAM, so the eviction above never got a chance before mbedtls_ssl_setup failed.
    conf.httpd.max_open_sockets = 2;
    conf.httpd.uri_match_fn = httpd_uri_match_wildcard;
    conf.httpd.max_uri_handlers = 12;
    httpd_handle_t server;
    if (httpd_ssl_start(&server, &conf) != ESP_OK) {
        Serial.println("HTTPS server failed to start");
        return;
    }
    const struct {
        const char* uri;
        httpd_method_t method;
        esp_err_t (*fn)(httpd_req_t*);
    } routes[] = {{"/meta", HTTP_GET, hGetMeta},        {"/meta", HTTP_PUT, hPutMeta},
                  {"/entries", HTTP_GET, hGetEntries},  {"/entries", HTTP_POST, hPostEntries},
                  {"/access", HTTP_POST, hAccess},      {"/devices", HTTP_GET, hDevices},
                  {"/devices/*", HTTP_DELETE, hRevoke}, {"/pin", HTTP_PUT, hSetPin},
                  {"/pin", HTTP_POST, hTryPin},         {"/pair/open", HTTP_POST, hOpenPair}};
    for (auto& rt : routes) {
        httpd_uri_t u = {};
        u.uri = rt.uri;
        u.method = rt.method;
        u.handler = rt.fn;
        httpd_register_uri_handler(server, &u);
    }
}

// ---- display ----

// The pairing QR (PROTOCOL.md §9) at the right edge: lit background, dark modules, 2 px per module, ~3 px quiet zone.
// Modules start on an even row: two-colour panels (rows 0-15 yellow, the rest blue, a gap between) then split
// between modules, not through one, which cameras can't read. Called back by esp_qrcode_generate().
void drawQr(esp_qrcode_handle_t qr) {
    const int size = esp_qrcode_get_size(qr), box = size * 2 + 6, x0 = OLED_W - box;
    const int top = ((OLED_H - size * 2) / 2) & ~1;  // the first module row
    oled.fillRect(x0, top - 3, box, box, SSD1306_WHITE);
    for (int y = 0; y < size; y++)
        for (int x = 0; x < size; x++)
            if (esp_qrcode_get_module(qr, x, y)) oled.fillRect(x0 + 3 + 2 * x, top + 2 * y, 2, 2, SSD1306_BLACK);
}

String apPass;  // the setup hotspot's password while it's up, else ""

// A labelled bar 60 px wide; with b >= 0, two thin bars (the two CPU cores)
void meter(int y, const char* label, int a, int b, const String& val) {
    oled.setCursor(0, y);
    oled.print(label);
    oled.drawRect(22, y, 62, 7, SSD1306_WHITE);
    if (b < 0) oled.fillRect(23, y + 1, a * 60 / 100, 5, SSD1306_WHITE);
    else {
        oled.fillRect(23, y + 1, a * 60 / 100, 2, SSD1306_WHITE);
        oled.fillRect(23, y + 4, b * 60 / 100, 2, SSD1306_WHITE);
    }
    oled.setCursor(88, y);
    oled.print(val);
}

// The idle screen: load per core, free heap, vault and app flash use, the IP, a hex stream and the odd glitch.
void drawStats() {
    // CPU: the idle task's run time (us, esp_timer) per core since the last frame
    static uint32_t idleWas[2];
    static int64_t at;
    int64_t now = esp_timer_get_time();
    int load[2] = {0, 0};
    for (int c = 0; c < 2; c++) {
        uint32_t idle = ulTaskGetIdleRunTimeCounterForCore(c);
        if (at) load[c] = constrain(100 - (int)((idle - idleWas[c]) * 100 / (now - at)), 0, 100);
        idleWas[c] = idle;
    }
    at = now;
    // usedBytes() walks the whole file system, so not every frame
    static uint32_t fsAt = 0;
    static int fsPct = 0;
    if (!fsAt || millis() - fsAt > 10000) {
        fsAt = millis() | 1;
        fsPct = LittleFS.usedBytes() * 100 / LittleFS.totalBytes();
    }
    static const int appPct = ESP.getSketchSize() * 100 / esp_ota_get_running_partition()->size;
    const uint32_t heap = ESP.getHeapSize(), free = ESP.getFreeHeap();

    static char hex[14] = "";  // shifts one character per frame
    memmove(hex, hex + 1, 12);
    hex[12] = "0123456789ABCDEF"[esp_random() & 15];
    oled.setCursor(0, 0);
    oled.print("PWVAULT");
    oled.setCursor(50, 0);
    oled.print(hex);
    oled.drawFastHLine(0, 10, OLED_W, SSD1306_WHITE);
    meter(14, "CPU", load[0], load[1], String(max(load[0], load[1])) + "%");
    meter(24, "RAM", 100 - free * 100 / heap, -1, String(free / 1024) + "K");
    meter(34, "FS", fsPct, -1, String(fsPct) + "%");
    meter(44, "ROM", appPct, -1, String(appPct) + "%");
    oled.setCursor(0, 56);
    if (WiFi.isConnected()) oled.print(WiFi.localIP());
    else oled.print("no wifi");  // the last IP would be misleading

    // Glitch, ~every 6 s at 5 fps: shift or invert one 8-px band of the frame buffer (a page: 128 column bytes)
    if (esp_random() % 30 == 0) {
        uint8_t* band = oled.getBuffer() + (esp_random() % (OLED_H / 8)) * OLED_W;
        if (esp_random() & 1) {
            const int by = 2 + esp_random() % 6;
            memmove(band + by, band, OLED_W - by);
            memset(band, 0, by);
        } else
            for (int x = 0; x < OLED_W; x++) band[x] ^= 0xFF;
    }
}

void draw() {
    oled.clearDisplay();
    oled.setTextColor(SSD1306_WHITE);
    oled.setTextWrap(false);
    oled.setTextSize(1);
    if (apPass.length()) {
        // Text on the left 64 px (10 characters), the join-Wi-Fi QR on the right, as for pairing
        oled.setCursor(0, 0);
        oled.print("wifi setup");
        oled.drawFastHLine(0, 10, 62, SSD1306_WHITE);
        // Labelled lines: the name right above the password read as one string ("pwvault-apczdxmj64zk")
        oled.setCursor(0, 14);
        oled.print("network");
        oled.setCursor(0, 23);
        oled.print(SETUP_SSID);
        oled.setCursor(0, 37);
        oled.print("password");
        oled.setCursor(0, 46);
        oled.print(apPass);
        esp_qrcode_config_t qr = ESP_QRCODE_CONFIG_DEFAULT();
        qr.display_func = drawQr;
        qr.max_qrcode_version = 3;  // 29 modules: 64 px with the quiet zone, the panel's height
        esp_qrcode_generate(&qr, ("WIFI:T:WPA;S:" + String(SETUP_SSID) + ";P:" + apPass + ";;").c_str());
    } else if (prompt.line1.length()) {
        oled.setCursor(0, 0);
        oled.println("confirm");
        oled.drawFastHLine(0, 10, OLED_W, SSD1306_WHITE);
        oled.setCursor(0, 16);
        oled.println(prompt.line1);
        oled.setCursor(0, 30);
        oled.println(prompt.line2);
        oled.setCursor(0, 50);
        oled.println("BOOT = yes");
    } else if (revokePending()) {
        oled.setCursor(0, 0);
        oled.println("revoke device?");
        oled.drawFastHLine(0, 10, OLED_W, SSD1306_WHITE);
        oled.setCursor(0, 16);
        oled.println(pendingRevoke.name);
        oled.setCursor(0, 30);
        oled.println("asked by " + pendingRevoke.by);
        oled.setCursor(0, 50);
        oled.println("BOOT = yes");
    } else if (pairServer) {
        // Text on the left 72 px (12 characters), the QR on the right; the QR is drawn last, so it wins any overlap
        // ponytail: an IP longer than 12 characters is cut off in the text; it's complete in the QR
        oled.setCursor(0, 0);
        oled.printf("pairing %lus", (unsigned long)(int32_t)(pairUntil - millis()) / 1000);
        oled.drawFastHLine(0, 10, 70, SSD1306_WHITE);
        oled.setCursor(0, 18);
        oled.print(pairCode.substring(0, 4) + "-" + pairCode.substring(4, 8));
        oled.setCursor(0, 28);
        oled.print(pairCode.substring(8, 12) + "-" + pairCode.substring(12));
        oled.setCursor(0, 42);
        oled.print(pairBy.isEmpty() ? "scan or type" : ("via " + pairBy).substring(0, 12));
        oled.setCursor(0, 56);
        oled.print(WiFi.localIP());
        esp_qrcode_config_t qr = ESP_QRCODE_CONFIG_DEFAULT();
        qr.display_func = drawQr;
        qr.max_qrcode_version = 3;  // <= 40 alphanumeric characters: version 2, 50 px
        esp_qrcode_generate(&qr, ("PWVAULT:" + WiFi.localIP().toString() + ":" + pairCode).c_str());
    } else if ((int32_t)(event.until - millis()) > 0) {
        oled.setCursor(0, 0);
        oled.println(event.who);
        oled.drawFastHLine(0, 10, OLED_W, SSD1306_WHITE);
        oled.setCursor(0, 16);
        oled.println(event.line1);
        oled.setCursor(0, 30);
        oled.println(event.line2);
        oled.setCursor(0, 50);
        oled.println(event.note);
    } else {
        drawStats();
    }
    oled.display();
}

// ---- Wi-Fi setup: a WPA2 hotspot whose random password is only on the OLED, and a page to pick the network ----

String htmlEscape(const String& in) {
    String out;
    for (char ch : in) out += ch == '<' ? "&lt;" : ch == '>' ? "&gt;" : ch == '&' ? "&amp;" : ch == '"' ? "&quot;" : String(ch);
    return out;
}

// Never returns: restarts once the board is on a network, the new one or the saved one coming back.
void runSetup() {
    WiFi.mode(WIFI_AP_STA);
    WiFi.disconnect();  // a station still connecting makes the scan fail
    String options, names;  // names: one SSID per line, for the phone app
    for (int i = 0, n = WiFi.scanNetworks(); i < n; i++) {
        options += "<option value=\"" + htmlEscape(WiFi.SSID(i)) + "\">";
        names += WiFi.SSID(i) + "\n";
        Serial.printf("scan: %s ch %d %d dBm auth %d\n", WiFi.SSID(i).c_str(), WiFi.channel(i), WiFi.RSSI(i),
                      WiFi.encryptionType(i));  // a join timing out below about -80 dBm is the signal, not the password
    }
    // A connecting station scans every channel and drags the hotspot along, so phones can't join it: no automatic
    // reconnects, and the saved network is retried (below) only while nobody is on the hotspot.
    WiFi.setAutoReconnect(false);
    const char* ALPHA = "23456789abcdefghjkmnpqrstuvwxyz";  // no 0 1 i l o: read off a small screen
    uint8_t raw[10];
    rng(nullptr, raw, sizeof raw);  // radio on: real entropy
    for (uint8_t b : raw) apPass += ALPHA[b % 31];
    WiFi.softAP(SETUP_SSID, apPass.c_str());
    Serial.printf("wifi setup: join %s, open http://%s\n", SETUP_SSID, WiFi.softAPIP().toString().c_str());

    DNSServer dns;  // every name resolves to us, so phones open the page as a captive portal
    dns.start(53, "*", WiFi.softAPIP());
    WebServer web(80);
    String ssid, pass;
    bool join = false;
    web.on("/", HTTP_GET, [&] {
        web.send(200, "text/html",
                 "<!doctype html><meta name=viewport content='width=device-width'><title>pwvault setup</title>"
                 "<body style='font:16px sans-serif;max-width:24em;margin:2em auto;padding:0 1em'>"
                 "<h2>pwvault Wi-Fi</h2><form method=post action=/join>"
                 "<p>Network<br><input name=ssid list=n required style='width:100%'><datalist id=n>" +
                     options +
                     "</datalist><p>Password<br><input name=pass type=password style='width:100%'>"
                     "<p><button>Connect</button></form><p><small>2.4 GHz networks only.</small>");
    });
    web.on("/networks", HTTP_GET, [&] { web.send(200, "text/plain", names); });
    web.on("/join", HTTP_POST, [&] {
        ssid = web.arg("ssid");
        pass = web.arg("pass");
        Serial.printf("wifi setup: joining %s\n", ssid.c_str());
        web.send(200, "text/html",
                 "<!doctype html><meta name=viewport content='width=device-width'>"
                 "<body style='font:16px sans-serif;max-width:24em;margin:2em auto;padding:0 1em'>"
                 "<h2>Connecting to " + htmlEscape(ssid) + "</h2><p>This hotspot goes away now. If the board's "
                 "screen shows its stats and an IP, it's online. If it shows the setup QR again, the password was "
                 "wrong: join again and retry.");
        join = true;
    });
    web.onNotFound([&] {  // captive-portal probes (generate_204, hotspot-detect.html, ...) land here
        web.sendHeader("Location", "http://" + WiFi.softAPIP().toString() + "/");
        web.send(302, "text/plain", "");
    });
    web.begin();

    for (uint32_t joinAt = 0, drawn = 0, retried = millis();; delay(10)) {
        dns.processNextRequest();
        web.handleClient();
        if (join && !joinAt) joinAt = millis() | 1;
        if (joinAt && millis() - joinAt > 1000) {  // after the reply has gone out
            join = false;
            joinAt = 0;
            WiFi.begin(ssid.c_str(), pass.c_str());  // saved to NVS: the next boot uses it
            for (uint32_t t = millis(); !WiFi.isConnected() && millis() - t < 20000;) delay(100);
            if (!WiFi.isConnected()) WiFi.disconnect();  // wrong password: stop trying, the hotspot stays usable
        }
        if (haveSavedWifi() && !joinAt && !WiFi.softAPgetStationNum() && millis() - retried > 60000) {
            retried = millis();
            WiFi.begin();  // the saved network may be back (a router slower to boot than the board)
        }
        if (WiFi.isConnected()) {
            Serial.printf("wifi: joined %s\n", WiFi.SSID().c_str());
            delay(500);
            ESP.restart();  // start clean, as a station only
        }
        if (millis() - drawn > 500) {
            drawn = millis();
            draw();
        }
    }
}

// Formats only storage that never held anything. A mount failure on used storage stops here instead of wiping the
// vault; holding BOOT for 10 s erases it on purpose (e.g. a board that had other firmware's data).
void mountStorage() {
    if (LittleFS.begin(false)) return;
    const esp_partition_t* part =
        esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, nullptr);
    bool blank = part;
    static uint32_t buf[1024];
    for (size_t off = 0; blank && off < part->size; off += sizeof buf) {
        blank = esp_partition_read(part, off, buf, sizeof buf) == ESP_OK;
        for (uint32_t w : buf) blank = blank && w == 0xFFFFFFFF;
    }
    if (blank && LittleFS.begin(true)) return;
    Serial.println("LittleFS mount failed; not formatting used storage");
    oled.clearDisplay();
    oled.setCursor(0, 0);
    oled.print("storage error\nnothing was erased\n\nhold BOOT 10 s to\nERASE the vault");
    oled.display();
    for (uint32_t heldAt = 0;; delay(50)) {
        if (digitalRead(BUTTON) == HIGH) heldAt = 0;
        else if (!heldAt) heldAt = millis() | 1;
        else if (millis() - heldAt > 10000) {
            LittleFS.format();
            ESP.restart();
        }
    }
}

bool haveSavedWifi() {
    wifi_config_t c = {};
    return esp_wifi_get_config(WIFI_IF_STA, &c) == ESP_OK && c.sta.ssid[0];
}

void setup() {
    Serial.begin(115200);
    Wire.begin(OLED_SDA, OLED_SCL);
    oled.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR);
    oled.clearDisplay();
    oled.setTextColor(SSD1306_WHITE);
    oled.setCursor(0, 0);
    oled.print("connecting wifi...");
    oled.display();
    pinMode(BUTTON, INPUT_PULLUP);
    attachInterrupt(digitalPinToInterrupt(BUTTON), onButton, FALLING);

    mountStorage();
    LittleFS.mkdir("/e");
    LittleFS.mkdir("/pin");
    seq = strtoull(readFile("/seq").c_str(), nullptr, 10);
    buildIndex();
    loadDevices();

    WiFi.setHostname(HOSTNAME);
    WiFi.mode(WIFI_STA);
    static uint8_t lastWhy = 0;
    WiFi.onEvent(  // why a join fails (wrong password, not found, WPA3 only...); each reason once in a row
        [](WiFiEvent_t, WiFiEventInfo_t info) {
            uint8_t why = info.wifi_sta_disconnected.reason;
            if (why != lastWhy)
                Serial.printf("wifi: %.32s: %s (%u)\n", (const char*)info.wifi_sta_disconnected.ssid,
                              WiFi.disconnectReasonName((wifi_err_reason_t)why), why);
            lastWhy = why;
        },
        ARDUINO_EVENT_WIFI_STA_DISCONNECTED);
    WiFi.onEvent(  // joined, password and all; online only once DHCP gives an address, which can fail on its own
        [](WiFiEvent_t, WiFiEventInfo_t info) {
            Serial.printf("wifi: associated with %.32s on channel %u, waiting for an address\n",
                          (const char*)info.wifi_sta_connected.ssid, info.wifi_sta_connected.channel);
            lastWhy = 0;
        },
        ARDUINO_EVENT_WIFI_STA_CONNECTED);
    if (!haveSavedWifi()) runSetup();
    WiFi.begin();  // the network saved by the setup page
    for (uint32_t t = millis(); !WiFi.isConnected(); delay(200))
        if (millis() - t > WIFI_WAIT_MS) runSetup();  // moved, or a new router: let someone pick the network
    Serial.printf("IP %s\n", WiFi.localIP().toString().c_str());
    if (!loadCa() || !loadServerCert()) {  // after Wi-Fi: the RNG needs the radio on for entropy
        Serial.println("device CA or server cert failed");
        showEvent("error", "certs failed", "", "");
    }
    configTime(0, 0, "pool.ntp.org", "time.google.com");  // UTC, for devices' last seen times
    MDNS.begin(HOSTNAME);
    MDNS.addService("https", "tcp", 443);
    startServer();
}

void loop() {
    static uint32_t heapAt = 0;  // DIAG: free heap, remove once the TLS allocation failures are understood
    if (millis() - heapAt > 10000) {
        heapAt = millis();
        Serial.printf("heap free %u, largest block %u, min ever %u\n", (unsigned)ESP.getFreeHeap(),
                      (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT), (unsigned)ESP.getMinFreeHeap());
    }
    static uint32_t wifiLost = 0;  // unattended device: if Wi-Fi stays down, retry from scratch, like at boot
    if (WiFi.isConnected()) wifiLost = 0;
    else if (!wifiLost) wifiLost = millis() | 1;
    else if (millis() - wifiLost > 60000) ESP.restart();
    if (pressed.exchange(false)) {
        bool revoked = false;
        if (ask == ASK_WAITING) {
            ask = ASK_YES;
        } else {
            std::lock_guard<std::mutex> g(mtx);
            if ((revoked = revokePending())) revokeNow();
        }
        if (ask == ASK_NONE && !revoked) {
            if (!pairServer) startPairing();
            else if (!pairBusy) stopPairing();  // pressed again: cancel
        }
    }
    if (openAsked) {
        if (!pairServer) startPairing();
        std::lock_guard<std::mutex> g(mtx);
        if (pairServer && pairBy.isEmpty()) pairBy = openBy;
        openAsked = false;
    }
    if (pairServer && !pairBusy && (pairDone || (int32_t)(millis() - pairUntil) > 0)) stopPairing();
    {
        std::unique_lock<std::mutex> g(mtx, std::try_to_lock);  // skip a frame rather than stall behind a request
        if (g.owns_lock()) draw();
    }
    delay(200);
}
