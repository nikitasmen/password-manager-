#include "error_utils.h"

namespace ErrorUtils {

void logError(const std::string& context, const std::string& message) {
    std::cerr << "Error in " << context << ": " << message << std::endl;
}

void logException(const std::string& context, const std::exception& e) {
    std::cerr << "Error in " << context << ": " << e.what() << std::endl;
}

void logWarning(const std::string& context, const std::string& message) {
    std::cerr << "Warning in " << context << ": " << message << std::endl;
}

}  // namespace ErrorUtils
