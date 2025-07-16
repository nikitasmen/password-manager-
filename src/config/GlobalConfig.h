#ifndef GLOBALCONFIG_H
#define GLOBALCONFIG_H

#include <string>
#include <vector> 

extern std::string g_data_path;  // Declare the global variable
extern std::vector<int> taps;          // Taps for a 3-bit LFSR (x^3 + x^1 + 1)
extern std::vector<int> init_state; // Initial state [1, 0, 1]
#endif // GLOBALCONFIG_H
