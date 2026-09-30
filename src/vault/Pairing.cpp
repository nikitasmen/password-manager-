#include "Pairing.h"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cctype>
#include <memory>
#include <nlohmann/json.hpp>

#include "../core/base64.h"
#include "Crypto.h"

namespace {

constexpr const char* kCertName = "pwvault.local";  // name baked into the ESP32's cert

template <class T, void (*Free)(T*)>
using Owned = std::unique_ptr<T, std::integral_constant<decltype(Free), Free>>;
using Pkey = Owned<EVP_PKEY, EVP_PKEY_free>;
using Cert = Owned<X509, X509_free>;
using Req = Owned<X509_REQ, X509_REQ_free>;
using Bio = Owned<BIO, BIO_free_all>;
using Curl = Owned<CURL, curl_easy_cleanup>;
using Slist = Owned<curl_slist, curl_slist_free_all>;

std::string bioString(BIO* b) {
    char* p = nullptr;
    long n = BIO_get_mem_data(b, &p);
    return std::string(p, n);
}

std::string der(X509* x) {
    std::string out(i2d_X509(x, nullptr), '\0');
    auto* p = reinterpret_cast<unsigned char*>(out.data());
    i2d_X509(x, &p);
    return out;
}

std::string sha256Hex(const std::string& data) {
    unsigned char h[32];
    unsigned int n = 0;
    EVP_Digest(data.data(), data.size(), h, &n, EVP_sha256(), nullptr);
    return vaultcrypto::toHex(std::string(reinterpret_cast<char*>(h), n));
}

size_t collect(char* data, size_t size, size_t n, void* out) {
    static_cast<std::string*>(out)->append(data, size * n);
    return size * n;
}

Slist resolveTo(const std::string& host, int port) {  // connect to host, verify the cert as pwvault.local
    return Slist(curl_slist_append(nullptr, (std::string(kCertName) + ":" + std::to_string(port) + ":" + host).c_str()));
}

// The cert the pairing port presents. Unverified here: the macs prove it's the board's.
std::string fetchServerCert(const std::string& host, int port) {
    Curl c(curl_easy_init());
    Slist resolve = resolveTo(host, port);
    std::string url = std::string("https://") + kCertName + ":" + std::to_string(port) + "/";
    curl_easy_setopt(c.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(c.get(), CURLOPT_RESOLVE, resolve.get());
    curl_easy_setopt(c.get(), CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c.get(), CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(c.get(), CURLOPT_CERTINFO, 1L);
    curl_easy_setopt(c.get(), CURLOPT_CONNECT_ONLY, 1L);  // the handshake is all we need
    curl_easy_setopt(c.get(), CURLOPT_CONNECTTIMEOUT_MS, 3000L);
    curl_easy_setopt(c.get(), CURLOPT_TIMEOUT, 10L);
    curl_certinfo* info = nullptr;
    if (curl_easy_perform(c.get()) != CURLE_OK || curl_easy_getinfo(c.get(), CURLINFO_CERTINFO, &info) != CURLE_OK ||
        !info || info->num_of_certs < 1)
        throw PairError("The board isn't in pairing mode at " + host + ". Press BOOT on it first: it then shows a code.");
    for (curl_slist* s = info->certinfo[0]; s; s = s->next)
        if (std::string(s->data).rfind("Cert:", 0) == 0) return s->data + 5;
    throw PairError("The board's certificate couldn't be read.");
}

}  // namespace

bool validDeviceName(const std::string& n) {
    if (n.empty() || n.size() > 20 || n[0] == '-') return false;
    for (char c : n)
        if (!std::isdigit(static_cast<unsigned char>(c)) && !(c >= 'a' && c <= 'z') && c != '-') return false;
    return true;
}

std::string normalizePairCode(const std::string& typed) {
    std::string code;
    for (char c : typed) {
        if (c == ' ' || c == '-') continue;
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        code += c == 'I' || c == 'L' ? '1' : c == 'O' ? '0' : c;  // Crockford base32: I/L read as 1, O as 0
    }
    return code.size() == 16 ? code : "";
}

PairedFiles pairWithBoard(const std::string& host, int pairPort, const std::string& name, const std::string& code) {
    if (!validDeviceName(name)) throw PairError("Use 1-20 characters of a-z, 0-9 and - for the name.");
    if (code.size() != 16) throw PairError("The code on the OLED has 16 characters.");
    PairedFiles out;
    out.serverPem = fetchServerCert(host, pairPort);
    Bio serverBio(BIO_new_mem_buf(out.serverPem.data(), static_cast<int>(out.serverPem.size())));
    Cert server(PEM_read_bio_X509(serverBio.get(), nullptr, nullptr, nullptr));
    if (!server) throw PairError("The board's certificate couldn't be read.");
    const std::string fp = sha256Hex(der(server.get()));

    // Our key and a certificate request for it, as base64 DER
    Pkey key(EVP_EC_gen("P-256"));
    Req req(X509_REQ_new());
    X509_NAME* subject = X509_REQ_get_subject_name(req.get());
    if (!key || !req ||
        !X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(name.c_str()),
                                    -1, -1, 0) ||
        !X509_REQ_set_pubkey(req.get(), key.get()) || !X509_REQ_sign(req.get(), key.get(), EVP_sha256()))
        throw std::runtime_error("OpenSSL: couldn't make a certificate request");
    std::string csrDer(i2d_X509_REQ(req.get(), nullptr), '\0');
    auto* p = reinterpret_cast<unsigned char*>(csrDer.data());
    i2d_X509_REQ(req.get(), &p);
    const std::string csr = base64::encode(csrDer);
    auto mac = [&](const std::string& msg) { return vaultcrypto::toHex(vaultcrypto::hmacSha256(code, msg)); };

    // POST /pair on a connection pinned to the cert we just fingerprinted
    const std::string body =
        nlohmann::json{{"name", name}, {"csr", csr}, {"mac", mac("pwvault-pair-req\n" + fp + "\n" + name + "\n" + csr)}}
            .dump();
    Curl c(curl_easy_init());
    Slist resolve = resolveTo(host, pairPort);
    Slist headers(curl_slist_append(nullptr, "Content-Type: application/json"));
    curl_blob pin{out.serverPem.data(), out.serverPem.size(), CURL_BLOB_COPY};
    std::string url = std::string("https://") + kCertName + ":" + std::to_string(pairPort) + "/pair", reply;
    curl_easy_setopt(c.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(c.get(), CURLOPT_RESOLVE, resolve.get());
    curl_easy_setopt(c.get(), CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(c.get(), CURLOPT_CAINFO_BLOB, &pin);
    curl_easy_setopt(c.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(c.get(), CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(c.get(), CURLOPT_CONNECTTIMEOUT_MS, 3000L);
    curl_easy_setopt(c.get(), CURLOPT_TIMEOUT, 90L);  // the board waits up to 60 s for the approving press
    curl_easy_setopt(c.get(), CURLOPT_WRITEFUNCTION, collect);
    curl_easy_setopt(c.get(), CURLOPT_WRITEDATA, &reply);
    if (CURLcode rc = curl_easy_perform(c.get()); rc != CURLE_OK)
        throw PairError(std::string("Lost the board while pairing: ") + curl_easy_strerror(rc) + ".");
    long status = 0;
    curl_easy_getinfo(c.get(), CURLINFO_RESPONSE_CODE, &status);
    nlohmann::json j = nlohmann::json::parse(reply, nullptr, false);
    if (status != 200) {
        std::string why = j.is_object() ? j.value("error", "") : "";
        throw PairError("The board said: " + (why.empty() ? "HTTP " + std::to_string(status) : why) +
                        ". Press BOOT to start over.");
    }
    const std::string certB64 = j.is_object() ? j.value("cert", "") : "";
    if (certB64.empty() || !j.is_object() || j.value("mac", "") != mac("pwvault-pair-resp\n" + fp + "\n" + certB64))
        throw PairError("The reply isn't signed with the code: someone may be intercepting. Nothing was saved.");

    const std::string certDer = base64::decode(certB64);
    auto* q = reinterpret_cast<const unsigned char*>(certDer.data());
    Cert cert(d2i_X509(nullptr, &q, static_cast<long>(certDer.size())));
    if (!cert || EVP_PKEY_eq(X509_get0_pubkey(cert.get()), key.get()) != 1)
        throw PairError("The board signed a different key. Nothing was saved.");
    Bio certBio(BIO_new(BIO_s_mem())), keyBio(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509(certBio.get(), cert.get());
    PEM_write_bio_PrivateKey(keyBio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr);
    out.certPem = bioString(certBio.get());
    out.keyPem = bioString(keyBio.get());
    return out;
}
