#include "clipboard.h"
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <ApplicationServices/ApplicationServices.h>
#include <CoreFoundation/CoreFoundation.h>
#elif defined(__linux__)
#include <unistd.h>
#include <sys/wait.h>
#endif

// ClipboardManager implementation
ClipboardManager& ClipboardManager::getInstance() {
    static ClipboardManager instance;
    return instance;
}

ClipboardManager::ClipboardManager() {
    #ifdef _WIN32
    strategy_ = std::make_unique<WindowsClipboardStrategy>();
    #elif defined(__APPLE__)
    strategy_ = std::make_unique<MacOSClipboardStrategy>();
    #elif defined(__linux__)
    strategy_ = std::make_unique<LinuxClipboardStrategy>();
    #else
    strategy_ = nullptr; // No platform support
    #endif
}

void ClipboardManager::copyToClipboard(const std::string& text) {
    if (!strategy_) {
        throw ClipboardError("Clipboard operations not supported on this platform");
    }
    strategy_->copyToClipboard(text);
}

std::string ClipboardManager::getFromClipboard() {
    if (!strategy_) {
        throw ClipboardError("Clipboard operations not supported on this platform");
    }
    return strategy_->getFromClipboard();
}

bool ClipboardManager::isAvailable() {
    if (!strategy_) {
        return false;
    }
    return strategy_->isAvailable();
}

void ClipboardManager::clearClipboard() {
    if (!strategy_) {
        throw ClipboardError("Clipboard operations not supported on this platform");
    }
    strategy_->clearClipboard();
}

#ifdef _WIN32
// Windows implementation
void WindowsClipboardStrategy::copyToClipboard(const std::string& text) {
    if (!OpenClipboard(nullptr)) {
        throw ClipboardError("Failed to open Windows clipboard");
    }
    
    if (!EmptyClipboard()) {
        CloseClipboard();
        throw ClipboardError("Failed to empty Windows clipboard");
    }
    
    // Allocate global memory for the text
    HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hGlobal) {
        CloseClipboard();
        throw ClipboardError("Failed to allocate memory for clipboard");
    }
    
    // Copy text to global memory
    char* pGlobal = static_cast<char*>(GlobalLock(hGlobal));
    if (!pGlobal) {
        GlobalFree(hGlobal);
        CloseClipboard();
        throw ClipboardError("Failed to lock clipboard memory");
    }
    
    strcpy_s(pGlobal, text.size() + 1, text.c_str());
    GlobalUnlock(hGlobal);
    
    // Set clipboard data
    if (!SetClipboardData(CF_TEXT, hGlobal)) {
        GlobalFree(hGlobal);
        CloseClipboard();
        throw ClipboardError("Failed to set Windows clipboard data");
    }
    
    CloseClipboard();
}

std::string WindowsClipboardStrategy::getFromClipboard() {
    if (!OpenClipboard(nullptr)) {
        throw ClipboardError("Failed to open Windows clipboard");
    }
    
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) {
        CloseClipboard();
        return ""; // No text data available
    }
    
    char* pData = static_cast<char*>(GlobalLock(hData));
    if (!pData) {
        CloseClipboard();
        throw ClipboardError("Failed to lock Windows clipboard data");
    }
    
    std::string result(pData);
    GlobalUnlock(hData);
    CloseClipboard();
    
    return result;
}

bool WindowsClipboardStrategy::isAvailable() {
    return true; // Windows clipboard is always available
}

void WindowsClipboardStrategy::clearClipboard() {
    copyToClipboard(""); // Clear by copying empty string
}
#endif

#ifdef __APPLE__
// macOS implementation
void MacOSClipboardStrategy::copyToClipboard(const std::string& text) {
    // SECURITY FIX: Use pipe to avoid command injection
    FILE* pipe = popen("pbcopy", "w");
    if (!pipe) {
        throw ClipboardError("Failed to open pbcopy pipe on macOS");
    }
    
    // Write directly to pipe without shell interpretation
    size_t written = fwrite(text.c_str(), 1, text.length(), pipe);
    int result = pclose(pipe);
    
    if (written != text.length() || result != 0) {
        throw ClipboardError("Failed to write to clipboard on macOS");
    }
}

std::string MacOSClipboardStrategy::getFromClipboard() {
    return executeCommandWithOutput("pbpaste");
}

bool MacOSClipboardStrategy::isAvailable() {
    return true; // macOS clipboard is always available
}

void MacOSClipboardStrategy::clearClipboard() {
    // SECURITY FIX: Use secure pipe method
    FILE* pipe = popen("pbcopy", "w");
    if (pipe) {
        pclose(pipe); // Close without writing anything to clear clipboard
    }
}

bool MacOSClipboardStrategy::executeCommand(const std::string& command) {
    int result = system(command.c_str());
    return result == 0;
}

std::string MacOSClipboardStrategy::executeCommandWithOutput(const std::string& command) {
    std::string result;
    FILE* pipe = popen(command.c_str(), "r");
    
    if (!pipe) {
        throw ClipboardError("Failed to execute command: " + command);
    }
    
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    
    int exitCode = pclose(pipe);
    if (exitCode != 0) {
        throw ClipboardError("Command failed with exit code: " + std::to_string(exitCode));
    }
    
    // Remove trailing newline if present
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    
    return result;
}
#endif

#ifdef __linux__
// Linux implementation
void LinuxClipboardStrategy::copyToClipboard(const std::string& text) {
    // SECURITY FIX: Use pipe to avoid command injection
    FILE* pipe = nullptr;
    
    // Try xclip first, then xsel as fallback
    if (system("which xclip >/dev/null 2>&1") == 0) {
        pipe = popen("xclip -selection clipboard", "w");
    } else if (system("which xsel >/dev/null 2>&1") == 0) {
        pipe = popen("xsel --clipboard --input", "w");
    } else {
        throw ClipboardError("Neither xclip nor xsel is available for clipboard operations");
    }
    
    if (!pipe) {
        throw ClipboardError("Failed to open clipboard pipe on Linux");
    }
    
    // Write directly to pipe without shell interpretation
    size_t written = fwrite(text.c_str(), 1, text.length(), pipe);
    int result = pclose(pipe);
    
    if (written != text.length() || result != 0) {
        throw ClipboardError("Failed to write to clipboard on Linux");
    }
}

std::string LinuxClipboardStrategy::getFromClipboard() {
    if (system("which xclip >/dev/null 2>&1") == 0) {
        return executeCommandWithOutput("xclip -selection clipboard -o");
    } else if (system("which xsel >/dev/null 2>&1") == 0) {
        return executeCommandWithOutput("xsel --clipboard --output");
    } else {
        throw ClipboardError("Neither xclip nor xsel is available for clipboard operations");
    }
}

bool LinuxClipboardStrategy::isAvailable() {
    // Check if xclip or xsel is available
    return (system("which xclip >/dev/null 2>&1") == 0) || 
           (system("which xsel >/dev/null 2>&1") == 0);
}

void LinuxClipboardStrategy::clearClipboard() {
    // SECURITY FIX: Use secure pipe method
    FILE* pipe = nullptr;
    
    if (system("which xclip >/dev/null 2>&1") == 0) {
        pipe = popen("xclip -selection clipboard", "w");
    } else if (system("which xsel >/dev/null 2>&1") == 0) {
        pipe = popen("xsel --clipboard --input", "w");
    }
    
    if (pipe) {
        pclose(pipe); // Close without writing anything to clear clipboard
    }
}

bool LinuxClipboardStrategy::executeCommand(const std::string& command) {
    int result = system(command.c_str());
    return result == 0;
}

std::string LinuxClipboardStrategy::executeCommandWithOutput(const std::string& command) {
    std::string result;
    FILE* pipe = popen(command.c_str(), "r");
    
    if (!pipe) {
        throw ClipboardError("Failed to execute command: " + command);
    }
    
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    
    int exitCode = pclose(pipe);
    if (exitCode != 0) {
        throw ClipboardError("Command failed with exit code: " + std::to_string(exitCode));
    }
    
    // Remove trailing newline if present
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    
    return result;
}
#endif
