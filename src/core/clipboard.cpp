#include "clipboard.h"
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <memory>
#include <cstring>  // For memcpy

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
    
    // Copy text to global memory using safe memcpy
    char* pGlobal = static_cast<char*>(GlobalLock(hGlobal));
    if (!pGlobal) {
        GlobalFree(hGlobal);
        CloseClipboard();
        throw ClipboardError("Failed to lock clipboard memory");
    }
    
    // SECURITY FIX: Use memcpy instead of strcpy_s to avoid buffer overflow issues
    // and properly handle passwords with special characters including null bytes
    std::memcpy(pGlobal, text.c_str(), text.size());
    pGlobal[text.size()] = '\0';  // Explicitly null-terminate
    GlobalUnlock(hGlobal);
    
    // Set clipboard data
    if (!SetClipboardData(CF_TEXT, hGlobal)) {
        GlobalFree(hGlobal);
        CloseClipboard();
        throw ClipboardError("Failed to set Windows clipboard data");
    }
    
    CloseClipboard();
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


#endif
