#ifndef CIPHER_CONTEXT_RAII_H
#define CIPHER_CONTEXT_RAII_H

#include <openssl/evp.h>
#include <memory>

/**
 * @class CipherContextRAII
 * @brief RAII wrapper for OpenSSL's EVP_CIPHER_CTX
 * 
 * This class provides RAII (Resource Acquisition Is Initialization) semantics
 * for OpenSSL's EVP_CIPHER_CTX, ensuring proper cleanup of resources.
 */
class CipherContextRAII {
private:
    EVP_CIPHER_CTX* ctx;
    
public:
    /**
     * @brief Default constructor
     */
    CipherContextRAII();
    
    /**
     * @brief Destructor - frees the EVP_CIPHER_CTX
     */
    ~CipherContextRAII();
    
    // Disable copy constructor and assignment operator
    CipherContextRAII(const CipherContextRAII&) = delete;
    CipherContextRAII& operator=(const CipherContextRAII&) = delete;
    
    /**
     * @brief Move constructor
     */
    CipherContextRAII(CipherContextRAII&& other) noexcept;
    
    /**
     * @brief Move assignment operator
     */
    CipherContextRAII& operator=(CipherContextRAII&& other) noexcept;
    
    /**
     * @brief Get the underlying EVP_CIPHER_CTX pointer
     * @return EVP_CIPHER_CTX* The underlying cipher context
     */
    EVP_CIPHER_CTX* get() const { return ctx; }
    
    /**
     * @brief Get the underlying EVP_CIPHER_CTX pointer
     * @return EVP_CIPHER_CTX* The underlying cipher context
     */
    operator EVP_CIPHER_CTX*() const { return ctx; }
};

#endif // CIPHER_CONTEXT_RAII_H
