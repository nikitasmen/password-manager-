#ifndef CLIPBOARD_H
#define CLIPBOARD_H

#include <string>
#include <stdexcept>
#include <memory>

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
 * @class IClipboardStrategy
 * @brief Abstract base class for platform-specific clipboard implementations
 */
class IClipboardStrategy {
public:
    virtual ~IClipboardStrategy() = default;
    
    /**
     * @brief Copy text to the system clipboard
     * @param text The text to copy to clipboard
     * @throws ClipboardError if the operation fails
     */
    virtual void copyToClipboard(const std::string& text) = 0;
    
    /**
     * @brief Get text from the system clipboard
     * @return The text content from clipboard
     * @throws ClipboardError if the operation fails
     */
    virtual std::string getFromClipboard() = 0;
    
    /**
     * @brief Check if clipboard functionality is available
     * @return true if clipboard operations are supported, false otherwise
     */
    virtual bool isAvailable() = 0;
    
    /**
     * @brief Clear the clipboard content
     * @throws ClipboardError if the operation fails
     */
    virtual void clearClipboard() = 0;
};

/**
 * @class WindowsClipboardStrategy
 * @brief Windows-specific clipboard implementation
 */
#ifdef _WIN32
class WindowsClipboardStrategy : public IClipboardStrategy {
public:
    void copyToClipboard(const std::string& text) override;
    std::string getFromClipboard() override;
    bool isAvailable() override;
    void clearClipboard() override;
};
#endif

/**
 * @class MacOSClipboardStrategy
 * @brief macOS-specific clipboard implementation
 */
#ifdef __APPLE__
class MacOSClipboardStrategy : public IClipboardStrategy {
public:
    void copyToClipboard(const std::string& text) override;
    std::string getFromClipboard() override;
    bool isAvailable() override;
    void clearClipboard() override;

private:
    bool executeCommand(const std::string& command);
    std::string executeCommandWithOutput(const std::string& command);
};
#endif

/**
 * @class LinuxClipboardStrategy
 * @brief Linux-specific clipboard implementation
 */
#ifdef __linux__
class LinuxClipboardStrategy : public IClipboardStrategy {
public:
    void copyToClipboard(const std::string& text) override;
    std::string getFromClipboard() override;
    bool isAvailable() override;
    void clearClipboard() override;

private:
    bool executeCommand(const std::string& command);
    std::string executeCommandWithOutput(const std::string& command);
};
#endif

/**
 * @class ClipboardManager
 * @brief Cross-platform clipboard management utility using strategy pattern
 * 
 * This class provides a unified interface for clipboard operations across different platforms.
 * It uses the strategy pattern to delegate platform-specific operations to appropriate implementations.
 */
class ClipboardManager {
public:
    /**
     * @brief Get the singleton instance of ClipboardManager
     * @return Reference to the ClipboardManager instance
     */
    static ClipboardManager& getInstance();
    
    /**
     * @brief Copy text to the system clipboard
     * @param text The text to copy to clipboard
     * @throws ClipboardError if the operation fails
     */
    void copyToClipboard(const std::string& text);
    
    /**
     * @brief Get text from the system clipboard
     * @return The text content from clipboard
     * @throws ClipboardError if the operation fails
     */
    std::string getFromClipboard();
    
    /**
     * @brief Check if clipboard functionality is available
     * @return true if clipboard operations are supported, false otherwise
     */
    bool isAvailable();
    
    /**
     * @brief Clear the clipboard content
     * @throws ClipboardError if the operation fails
     */
    void clearClipboard();

private:
    ClipboardManager();
    std::unique_ptr<IClipboardStrategy> strategy_;
    
    // Singleton pattern - delete copy constructor and assignment operator
    ClipboardManager(const ClipboardManager&) = delete;
    ClipboardManager& operator=(const ClipboardManager&) = delete;
};

#endif // CLIPBOARD_H
