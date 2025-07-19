#ifndef CLIPBOARD_H
#define CLIPBOARD_H

#include <string>
#include <stdexcept>

/**
 * @class ClipboardError
 * @brief Exception class for clipboard-related errors
 */
class ClipboardError : public std::runtime_error {
public:
    explicit ClipboardError(const std::string& message) 
        : std::runtime_error("Clipboard Error: " + message) {}
};

/**
 * @class ClipboardManager
 * @brief Cross-platform clipboard management utility
 * 
 * This class provides a unified interface for clipboard operations across different platforms.
 * It supports Windows, macOS, and Linux systems with appropriate fallback mechanisms.
 */
class ClipboardManager {
public:
    /**
     * @brief Copy text to the system clipboard
     * @param text The text to copy to clipboard
     * @throws ClipboardError if the operation fails
     */
    static void copyToClipboard(const std::string& text);
    
    /**
     * @brief Get text from the system clipboard
     * @return The text content from clipboard
     * @throws ClipboardError if the operation fails
     */
    static std::string getFromClipboard();
    
    /**
     * @brief Check if clipboard functionality is available
     * @return true if clipboard operations are supported, false otherwise
     */
    static bool isAvailable();
    
    /**
     * @brief Clear the clipboard content
     * @throws ClipboardError if the operation fails
     */
    static void clearClipboard();

private:
    // Platform-specific implementation methods
    #ifdef _WIN32
    static void copyToClipboardWindows(const std::string& text);
    static std::string getFromClipboardWindows();
    #elif defined(__APPLE__)
    static void copyToClipboardMacOS(const std::string& text);
    static std::string getFromClipboardMacOS();
    #elif defined(__linux__)
    static void copyToClipboardLinux(const std::string& text);
    static std::string getFromClipboardLinux();
    #endif
    
    // Helper methods
    static bool executeCommand(const std::string& command);
    static std::string executeCommandWithOutput(const std::string& command);
};

#endif // CLIPBOARD_H
