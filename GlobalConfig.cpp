#include "GlobalConfig.h"

std::string data_path = "./data";  // Default to current directory if not set elsewhere
std::vector<int> taps = {0, 2};          // Taps for a 3-bit LFSR (x^3 + x^1 + 1)
std::vector<int> init_state = {1, 0, 1}; // Initial state [1, 0, 1]