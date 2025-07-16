#include <iostream>
#include <string>
#include "../src/core/base64.h"

int main() {
    // Test with regular alphanumeric text
    std::string regular = "Hello123World";
    std::string encoded = Base64::encode(regular);
    std::string decoded = Base64::decode(encoded);
    
    std::cout << "Regular text test:" << std::endl;
    std::cout << "Original: " << regular << std::endl;
    std::cout << "Encoded: " << encoded << std::endl;
    std::cout << "Decoded: " << decoded << std::endl;
    std::cout << "Match: " << (regular == decoded ? "YES" : "NO") << std::endl;
    std::cout << std::endl;
    
    // Test with special characters and symbols
    std::string symbols = "!@#$%^&*()_+-=[]{}|;':\",./<>?\\`~";
    encoded = Base64::encode(symbols);
    decoded = Base64::decode(encoded);
    
    std::cout << "Symbols test:" << std::endl;
    std::cout << "Original: " << symbols << std::endl;
    std::cout << "Encoded: " << encoded << std::endl;
    std::cout << "Decoded: " << decoded << std::endl;
    std::cout << "Match: " << (symbols == decoded ? "YES" : "NO") << std::endl;
    std::cout << std::endl;
    
    // Test with Unicode characters
    std::string unicode = "你好，世界! Привет мир! こんにちは世界!";
    encoded = Base64::encode(unicode);
    decoded = Base64::decode(encoded);
    
    std::cout << "Unicode test:" << std::endl;
    std::cout << "Original: " << unicode << std::endl;
    std::cout << "Encoded: " << encoded << std::endl;
    std::cout << "Decoded: " << decoded << std::endl;
    std::cout << "Match: " << (unicode == decoded ? "YES" : "NO") << std::endl;
    
    return 0;
}
