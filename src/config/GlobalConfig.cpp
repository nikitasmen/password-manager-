#include "GlobalConfig.h"

// Updated to use a path relative to the executable location
std::string data_path = "./build/data";  // Store in the build/data directory
std::vector<int> taps = {0, 2};          // Taps for a 3-bit LFSR (x^3 + x^1 + 1)
std::vector<int> init_state = {1, 0, 1}; // Initial state [1, 0, 1]