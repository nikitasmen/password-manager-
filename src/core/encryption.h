#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>

class Encryption {
private:
    std::vector<int> taps;
    std::vector<int> state;

public:
    Encryption(const std::vector<int>& taps, const std::vector<int>& init_state);

    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& encrypted_text);
};

#endif // ENCRYPTION_H
