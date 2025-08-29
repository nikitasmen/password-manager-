#ifndef BASE64_H
#define BASE64_H

#include <string>

namespace Base64 {
/**
 * @brief Encode binary data to Base64 string
 *
 * @param data Binary data to encode
 * @return std::string Base64 encoded string
 */
std::string encode(const std::string& data);

/**
 * @brief Decode Base64 string to binary data
 *
 * @param base64 Base64 string to decode
 * @return std::string Decoded binary data
 */
std::string decode(const std::string& base64);
}  // namespace Base64

#endif  // BASE64_H
