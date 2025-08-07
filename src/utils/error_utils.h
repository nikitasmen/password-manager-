#ifndef ERROR_UTILS_H
#define ERROR_UTILS_H

#include <string>
#include <iostream>

/**
 * @brief Common error handling utilities to reduce code duplication
 */
namespace ErrorUtils {
    /**
     * @brief Log an error with consistent formatting
     * @param context The context where the error occurred (e.g., function name)
     * @param message The error message
     */
    void logError(const std::string& context, const std::string& message);
    
    /**
     * @brief Log an exception with consistent formatting
     * @param context The context where the exception occurred
     * @param e The exception that was caught
     */
    void logException(const std::string& context, const std::exception& e);
    
    /**
     * @brief Log a warning with consistent formatting
     * @param context The context for the warning
     * @param message The warning message
     */
    void logWarning(const std::string& context, const std::string& message);
}

#endif // ERROR_UTILS_H
