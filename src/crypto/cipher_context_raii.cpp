#include "cipher_context_raii.h"
#include <stdexcept>
#include <openssl/err.h>

CipherContextRAII::CipherContextRAII() {
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }
}

CipherContextRAII::~CipherContextRAII() {
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = nullptr;
    }
}

CipherContextRAII::CipherContextRAII(CipherContextRAII&& other) noexcept {
    ctx = other.ctx;
    other.ctx = nullptr;
}

CipherContextRAII& CipherContextRAII::operator=(CipherContextRAII&& other) noexcept {
    if (this != &other) {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
        ctx = other.ctx;
        other.ctx = nullptr;
    }
    return *this;
}
