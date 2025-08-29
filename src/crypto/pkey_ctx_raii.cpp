#include "pkey_ctx_raii.h"

#include <openssl/err.h>

PKEYContextRAII::PKEYContextRAII(EVP_PKEY* pkey) {
    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }
}

PKEYContextRAII::PKEYContextRAII(int key_type) {
    ctx = EVP_PKEY_CTX_new_id(key_type, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX for key generation");
    }
}

PKEYContextRAII::~PKEYContextRAII() {
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
        ctx = nullptr;
    }
}

PKEYContextRAII::PKEYContextRAII(PKEYContextRAII&& other) noexcept {
    ctx = other.ctx;
    other.ctx = nullptr;
}

PKEYContextRAII& PKEYContextRAII::operator=(PKEYContextRAII&& other) noexcept {
    if (this != &other) {
        if (ctx) {
            EVP_PKEY_CTX_free(ctx);
        }
        ctx = other.ctx;
        other.ctx = nullptr;
    }
    return *this;
}

EVP_PKEY_CTX* PKEYContextRAII::get() const {
    return ctx;
}

PKEYContextRAII::operator bool() const {
    return ctx != nullptr;
}
