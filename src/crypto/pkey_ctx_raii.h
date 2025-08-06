#ifndef PKEY_CTX_RAII_H
#define PKEY_CTX_RAII_H

#include <openssl/evp.h>
#include <stdexcept>

/**
 * @class PKEYContextRAII
 * @brief RAII wrapper for OpenSSL's EVP_PKEY_CTX
 * 
 * This class provides RAII (Resource Acquisition Is Initialization) semantics
 * for OpenSSL's EVP_PKEY_CTX, ensuring proper cleanup of resources.
 */
class PKEYContextRAII {
private:
    EVP_PKEY_CTX* ctx;

public:
    /**
     * @brief Construct PKEYContextRAII with existing EVP_PKEY
     */
    explicit PKEYContextRAII(EVP_PKEY* pkey);
    
    /**
     * @brief Construct PKEYContextRAII for key generation
     */
    explicit PKEYContextRAII(int key_type);
    
    /**
     * @brief Destructor - automatically frees the context
     */
    ~PKEYContextRAII();
    
    // Delete copy constructor and assignment operator
    PKEYContextRAII(const PKEYContextRAII&) = delete;
    PKEYContextRAII& operator=(const PKEYContextRAII&) = delete;
    
    // Move constructor and assignment operator
    PKEYContextRAII(PKEYContextRAII&& other) noexcept;
    PKEYContextRAII& operator=(PKEYContextRAII&& other) noexcept;
    
    /**
     * @brief Get the raw context pointer
     */
    EVP_PKEY_CTX* get() const;
    
    /**
     * @brief Check if context is valid
     */
    operator bool() const;
};

#endif // PKEY_CTX_RAII_H
