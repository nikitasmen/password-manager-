// ESP32 vault store: docs/PROTOCOL.md §6-7. Zero-knowledge: it stores ciphertext records and never sees a key.
// Mutual TLS: the board is its own device CA. Only certificates it issued, and hasn't revoked, get in.
// The OLED shows the clock, and which device read which entry (from the client's display hint).
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
//                  /devices.json  {name: hex SHA-256 of its current cert}; a name not in it is revoked
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ArduinoJson.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <WiFi.h>
#include <Wire.h>
#include <esp_https_server.h>
#include <esp_tls.h>
#include <esp_random.h>
#include <mbedtls/base64.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

#include <atomic>
#include <mutex>
#include <vector>

#include "cert.h"     // server cert: ../pki.sh server
#include "secrets.h"  // Wi-Fi: copy from secrets.example.h

// Hardware: found by I2C scan on this board
constexpr int OLED_SDA = 21, OLED_SCL = 22, OLED_ADDR = 0x3C, OLED_W = 128, OLED_H = 64;
constexpr int BUTTON = 0;  // BOOT, active low

constexpr const char* TZ_INFO = "EET-2EEST,M3.5.0/3,M10.5.0/4";  // Europe/Athens
constexpr const char* HOSTNAME = "pwvault";                      // pwvault.local, must match the cert
constexpr uint32_t EVENT_SHOW_MS = 8000;
constexpr size_t MAX_BODY = 16 * 1024;
constexpr size_t MAX_BATCH = 32;
constexpr uint16_t PAIR_PORT = 8444;
constexpr uint32_t PAIR_MS = 120000, CONFIRM_MS = 60000;

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

// Entry ids become file names, so accept exactly 32 lowercase hex chars and nothing else.
bool validId(const char* id) {
    if (!id || strlen(id) != 32) return false;
    for (const char* p = id; *p; p++)
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
        if (!deserializeJson(d, f) && validId(f.name())) indexPut(f.name(), d["seq"].as<uint64_t>());
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

String derToPem(const String& der) {
    size_t n;
    std::vector<uint8_t> b64(der.length() * 4 / 3 + 4);
    mbedtls_base64_encode(b64.data(), b64.size(), &n, (const uint8_t*)der.c_str(), der.length());
    String pem = "-----BEGIN CERTIFICATE-----\n";
    for (size_t i = 0; i < n; i += 64) pem += String((const char*)b64.data() + i, min<size_t>(64, n - i)) + "\n";
    return pem + "-----END CERTIFICATE-----\n";
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
    if (!der.length()) return false;
    caPem = derToPem(der);
    // cert last: a crash in between leaves no /ca.pem, so the next boot starts over
    return writeFile("/ca.key", (const char*)pem.data()) && writeFile("/ca.pem", caPem);
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
        if (!validId(e["id"]) || !e["updated"].is<int64_t>() || !e["deleted"].is<bool>() ||
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
    String out;
    serializeJson(d, out);
    return sendJson(r, "200 OK", out);
}

// DELETE /devices/<name>: needs a BOOT press, so a stolen device can't lock out the others.
// ponytail: blocks the main server (other clients' requests wait) until pressed or CONFIRM_MS; rare enough
esp_err_t hRevoke(httpd_req_t* r) {
    String name = r->uri + strlen("/devices/"), by;
    {
        std::lock_guard<std::mutex> g(mtx);
        const char* who = authDevice(r);
        if (!who) return forbid(r);
        if (!findDevice(name)) return fail(r, "404 Not Found", "no such device");
        by = who;
    }
    if (!confirm("revoke device?", name, CONFIRM_MS)) return fail(r, "403 Forbidden", "not confirmed on the board");
    std::lock_guard<std::mutex> g(mtx);
    for (size_t i = 0; i < devices.size(); i++)
        if (devices[i].name == name) devices.erase(devices.begin() + i);
    if (!saveDevices()) return fail(r, "500 Internal Server Error", "write failed");
    showEvent(by.c_str(), "revoked", name, "saved");
    return ok(r);
}

// ---- pairing server (PAIR_PORT, no client cert, only while pairing mode is on) ----

httpd_handle_t pairServer = nullptr;
uint32_t pairUntil = 0;
String pairCode;                                    // the HMAC key: 16 chars, 80 bits
std::atomic<bool> pairBusy{false}, pairDone{false};  // loop() closes pairing once a request has been handled

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
    conf.servercert = (const uint8_t*)CERT_PEM;
    conf.servercert_len = sizeof CERT_PEM;
    conf.prvtkey_pem = (const uint8_t*)KEY_PEM;
    conf.prvtkey_len = sizeof KEY_PEM;
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
}

void startServer() {
    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.servercert = (const uint8_t*)CERT_PEM;
    conf.servercert_len = sizeof CERT_PEM;
    conf.prvtkey_pem = (const uint8_t*)KEY_PEM;
    conf.prvtkey_len = sizeof KEY_PEM;
    conf.cacert_pem = (const uint8_t*)caPem.c_str();  // setting this makes a client certificate mandatory
    conf.cacert_len = caPem.length() + 1;
    conf.user_cb = onSession;
    conf.httpd.stack_size = 16384;       // TLS + JSON
    conf.httpd.lru_purge_enable = true;  // clients keep connections open; evict the idlest instead of refusing
    conf.httpd.uri_match_fn = httpd_uri_match_wildcard;
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
                  {"/devices/*", HTTP_DELETE, hRevoke}};
    for (auto& rt : routes) {
        httpd_uri_t u = {};
        u.uri = rt.uri;
        u.method = rt.method;
        u.handler = rt.fn;
        httpd_register_uri_handler(server, &u);
    }
}

// ---- display ----

void draw() {
    oled.clearDisplay();
    oled.setTextColor(SSD1306_WHITE);
    oled.setTextWrap(false);
    oled.setTextSize(1);
    if (prompt.line1.length()) {
        oled.setCursor(0, 0);
        oled.println("confirm");
        oled.drawFastHLine(0, 10, OLED_W, SSD1306_WHITE);
        oled.setCursor(0, 16);
        oled.println(prompt.line1);
        oled.setCursor(0, 30);
        oled.println(prompt.line2);
        oled.setCursor(0, 50);
        oled.println("BOOT = yes");
    } else if (pairServer) {
        oled.setCursor(0, 0);
        oled.printf("pairing  %lus", (unsigned long)(int32_t)(pairUntil - millis()) / 1000);
        oled.drawFastHLine(0, 10, OLED_W, SSD1306_WHITE);
        oled.setCursor(0, 20);
        for (int i = 0; i < 16; i += 4) oled.print(pairCode.substring(i, i + 4) + (i < 12 ? "-" : ""));
        oled.setCursor(0, 36);
        oled.print("pki.sh pair <name>");
        oled.setCursor(0, 56);
        oled.print(WiFi.localIP());
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
        struct tm t;
        char buf[24];
        if (getLocalTime(&t, 0)) {
            strftime(buf, sizeof buf, "%H:%M:%S", &t);
            oled.setTextSize(2);
            oled.setCursor(16, 8);
            oled.print(buf);
            strftime(buf, sizeof buf, "%a %d %b %Y", &t);
            oled.setTextSize(1);
            oled.setCursor(19, 32);
            oled.print(buf);
        } else {
            oled.setCursor(0, 16);
            oled.print(WiFi.isConnected() ? "syncing time..." : "no wifi");
        }
        oled.setCursor(0, 56);
        if (WiFi.isConnected()) oled.print(WiFi.localIP());
        else oled.print("no wifi");  // the last IP would be misleading
    }
    oled.display();
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

    if (!LittleFS.begin(true)) Serial.println("LittleFS mount failed");
    LittleFS.mkdir("/e");
    seq = strtoull(readFile("/seq").c_str(), nullptr, 10);
    buildIndex();
    loadDevices();
    mbedtls_x509_crt own;
    mbedtls_x509_crt_init(&own);
    if (!mbedtls_x509_crt_parse(&own, (const uint8_t*)CERT_PEM, sizeof CERT_PEM))
        serverFp = sha256Hex(own.raw.p, own.raw.len);
    mbedtls_x509_crt_free(&own);

    WiFi.setHostname(HOSTNAME);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    for (uint32_t t = millis(); !WiFi.isConnected(); delay(200))
        if (millis() - t > 30000) ESP.restart();  // unattended device: retry from scratch rather than hang
    Serial.printf("IP %s\n", WiFi.localIP().toString().c_str());
    if (!loadCa()) {  // after Wi-Fi: the RNG needs the radio on for entropy
        Serial.println("device CA failed");
        showEvent("error", "device CA failed", "", "");
    }
    configTzTime(TZ_INFO, "pool.ntp.org", "time.google.com");
    MDNS.begin(HOSTNAME);
    MDNS.addService("https", "tcp", 443);
    startServer();
}

void loop() {
    static uint32_t wifiLost = 0;  // unattended device: if Wi-Fi stays down, retry from scratch, like at boot
    if (WiFi.isConnected()) wifiLost = 0;
    else if (!wifiLost) wifiLost = millis() | 1;
    else if (millis() - wifiLost > 60000) ESP.restart();
    if (pressed.exchange(false)) {
        if (ask == ASK_WAITING) ask = ASK_YES;
        else if (!pairServer) startPairing();
        else if (!pairBusy) stopPairing();  // pressed again: cancel
    }
    if (pairServer && !pairBusy && (pairDone || (int32_t)(millis() - pairUntil) > 0)) stopPairing();
    {
        std::unique_lock<std::mutex> g(mtx, std::try_to_lock);  // skip a frame rather than stall behind a request
        if (g.owns_lock()) draw();
    }
    delay(200);
}
