#ifndef OPENSSL_UTIL_H
#define OPENSSL_UTIL_H

// OpenSSL handles that free themselves, and the conversions pairing (Pairing.cpp) and hosting (Serve.cpp) share.

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <memory>
#include <string>
#include <type_traits>

template <class T, void (*Free)(T*)>
using Owned = std::unique_ptr<T, std::integral_constant<decltype(Free), Free>>;
using Pkey = Owned<EVP_PKEY, EVP_PKEY_free>;
using Cert = Owned<X509, X509_free>;
using Req = Owned<X509_REQ, X509_REQ_free>;
using Bio = Owned<BIO, BIO_free_all>;

inline std::string bioString(BIO* b) {  // what was written to a memory BIO
    char* p = nullptr;
    long n = BIO_get_mem_data(b, &p);
    return std::string(p, n);
}

inline std::string der(X509* x) {
    std::string out(i2d_X509(x, nullptr), '\0');
    auto* p = reinterpret_cast<unsigned char*>(out.data());
    i2d_X509(x, &p);
    return out;
}

inline Cert readCert(const std::string& pem) {  // null if it isn't one
    Bio b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    return Cert(PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr));
}

#endif  // OPENSSL_UTIL_H
