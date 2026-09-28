// ESP32 vault store: docs/PROTOCOL.md §6-7. Zero-knowledge: it stores ciphertext records and never sees a key.
// Mutual TLS: only devices with a certificate from our device CA (esp32/pki.sh) can even complete the handshake.
// The OLED shows the clock, and which device read which entry (from the client's display hint).
//
// LittleFS layout: /meta.json   vault meta, verbatim
//                  /seq         store sequence counter
//                  /e/<id>      one entry record (JSON) per file
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ArduinoJson.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <WiFi.h>
#include <Wire.h>
#include <esp_https_server.h>
#include <esp_tls.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <mutex>
#include <vector>

#include "cert.h"     // server cert: ../pki.sh server
#include "devices.h"  // device CA + revoked devices: ../pki.sh init / revoke
#include "secrets.h"  // Wi-Fi: copy from secrets.example.h

// Hardware: found by I2C scan on this board
constexpr int OLED_SDA = 21, OLED_SCL = 22, OLED_ADDR = 0x3C, OLED_W = 128, OLED_H = 64;

constexpr const char* TZ_INFO = "EET-2EEST,M3.5.0/3,M10.5.0/4";  // Europe/Athens
constexpr const char* HOSTNAME = "pwvault";                      // pwvault.local, must match the cert
constexpr uint32_t EVENT_SHOW_MS = 8000;
constexpr size_t MAX_BODY = 16 * 1024;
constexpr size_t MAX_BATCH = 32;

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

// ---- http helpers ----

// The handshake already rejected anyone without a certificate signed by our device CA. When a session opens we
// remember its certificate's CN (the device name shown on the OLED) by socket; requests look it up.
// Only touched from the httpd task (session callback + handlers), so no lock needed.
struct Session {
    int fd = -1;
    char name[24] = "";
} sessions[8];  // > max_open_sockets

bool isRevoked(const char* name) {
    for (const char* const* rv = REVOKED_DEVICES; *rv; rv++)
        if (!strcmp(*rv, name)) return true;
    return false;
}

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
        return;
    }
}

// Device name for this request, or nullptr if the device is revoked (or its cert has no CN).
const char* authDevice(httpd_req_t* r) {
    int fd = httpd_req_to_sockfd(r);
    for (const Session& s : sessions)
        if (s.fd == fd) return isRevoked(s.name) ? nullptr : s.name;
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

// Returns nullptr and replies with the error itself on failure.
const char* readBody(httpd_req_t* r, JsonDocument& doc) {
    const char* who = authDevice(r);
    if (!who) return forbid(r), nullptr;
    size_t n = r->content_len;
    if (n > MAX_BODY) return fail(r, "413 Payload Too Large", "body too large"), nullptr;
    std::vector<char> body(n);
    for (size_t got = 0; got < n;) {
        int k = httpd_req_recv(r, &body[got], n - got);
        if (k <= 0) return fail(r, "400 Bad Request", "short body"), nullptr;
        got += k;
    }
    if (deserializeJson(doc, (const char*)body.data(), n)) return fail(r, "400 Bad Request", "bad json"), nullptr;
    return who;
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

void startServer() {
    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.servercert = (const uint8_t*)CERT_PEM;
    conf.servercert_len = sizeof CERT_PEM;
    conf.prvtkey_pem = (const uint8_t*)KEY_PEM;
    conf.prvtkey_len = sizeof KEY_PEM;
    conf.cacert_pem = (const uint8_t*)DEVICE_CA_PEM;  // setting this makes a client certificate mandatory
    conf.cacert_len = sizeof DEVICE_CA_PEM;
    conf.user_cb = onSession;
    conf.httpd.stack_size = 16384;       // TLS + JSON
    conf.httpd.lru_purge_enable = true;  // clients keep connections open; evict the idlest instead of refusing
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
                  {"/access", HTTP_POST, hAccess}};
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
    if ((int32_t)(event.until - millis()) > 0) {
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
        oled.print(WiFi.localIP());
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

    if (!LittleFS.begin(true)) Serial.println("LittleFS mount failed");
    LittleFS.mkdir("/e");
    seq = strtoull(readFile("/seq").c_str(), nullptr, 10);
    buildIndex();

    WiFi.setHostname(HOSTNAME);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    for (uint32_t t = millis(); !WiFi.isConnected(); delay(200))
        if (millis() - t > 30000) ESP.restart();  // unattended device: retry from scratch rather than hang
    Serial.printf("IP %s\n", WiFi.localIP().toString().c_str());
    configTzTime(TZ_INFO, "pool.ntp.org", "time.google.com");
    MDNS.begin(HOSTNAME);
    MDNS.addService("https", "tcp", 443);
    startServer();
}

void loop() {
    {
        std::unique_lock<std::mutex> g(mtx, std::try_to_lock);  // skip a frame rather than stall behind a request
        if (g.owns_lock()) draw();
    }
    delay(200);
}
