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

void ClipboardManager::copyToClipboard(const std::string& text) {
    try {
        #ifdef _WIN32
        copyToClipboardWindows(text);
        #elif defined(__APPLE__)
        copyToClipboardMacOS(text);
        #elif defined(__linux__)
        copyToClipboardLinux(text);
        #else
        throw ClipboardError("Clipboard operations not supported on this platform");
        #endif
    } catch (const std::exception& e) {
        throw ClipboardError("Failed to copy to clipboard: " + std::string(e.what()));
    }
}

std::string ClipboardManager::getFromClipboard() {
    try {
        #ifdef _WIN32
        return getFromClipboardWindows();
        #elif defined(__APPLE__)
        return getFromClipboardMacOS();
        #elif defined(__linux__)
        return getFromClipboardLinux();
        #else
        throw ClipboardError("Clipboard operations not supported on this platform");
        #endif
    } catch (const std::exception& e) {
        throw ClipboardError("Failed to get from clipboard: " + std::string(e.what()));
    }
}

bool ClipboardManager::isAvailable() {
    #ifdef _WIN32
    return true; // Windows clipboard is always available
    #elif defined(__APPLE__)
    return true; // macOS clipboard is always available
    #elif defined(__linux__)
    // Check if xclip or xsel is available
    return (system("which xclip >/dev/null 2>&1") == 0) || 
           (system("which xsel >/dev/null 2>&1") == 0);
    #else
    return false;
    #endif
}

void ClipboardManager::clearClipboard() {
    copyToClipboard(""); // Clear by copying empty string
}

#ifdef _WIN32
void ClipboardManager::copyToClipboardWindows(const std::string& text) {
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

std::string ClipboardManager::getFromClipboardWindows() {
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
#endif

#ifdef __APPLE__
void ClipboardManager::copyToClipboardMacOS(const std::string& text) {
    // Use pbcopy command for simplicity
    std::string command = "echo '" + text + "' | pbcopy";
    if (!executeCommand(command)) {
        throw ClipboardError("Failed to execute pbcopy command");
    }
}

std::string ClipboardManager::getFromClipboardMacOS() {
    return executeCommandWithOutput("pbpaste");
}
#endif

#ifdef __linux__
void ClipboardManager::copyToClipboardLinux(const std::string& text) {
    // Try xclip first, then xsel as fallback
    std::string command;
    if (system("which xclip >/dev/null 2>&1") == 0) {
        command = "echo '" + text + "' | xclip -selection clipboard";
    } else if (system("which xsel >/dev/null 2>&1") == 0) {
        command = "echo '" + text + "' | xsel --clipboard --input";
    } else {
        throw ClipboardError("Neither xclip nor xsel is available for clipboard operations");
    }
    
    if (!executeCommand(command)) {
        throw ClipboardError("Failed to execute clipboard command");
    }
}

std::string ClipboardManager::getFromClipboardLinux() {
    if (system("which xclip >/dev/null 2>&1") == 0) {
        return executeCommandWithOutput("xclip -selection clipboard -o");
    } else if (system("which xsel >/dev/null 2>&1") == 0) {
        return executeCommandWithOutput("xsel --clipboard --output");
    } else {
        throw ClipboardError("Neither xclip nor xsel is available for clipboard operations");
    }
}
#endif

bool ClipboardManager::executeCommand(const std::string& command) {
    int result = system(command.c_str());
    return result == 0;
}

std::string ClipboardManager::executeCommandWithOutput(const std::string& command) {
    std::string result;
    
    #ifdef _WIN32
    // Use _popen on Windows
    FILE* pipe = _popen(command.c_str(), "r");
    #else
    // Use popen on Unix-like systems
    FILE* pipe = popen(command.c_str(), "r");
    #endif
    
    if (!pipe) {
        throw ClipboardError("Failed to execute command: " + command);
    }
    
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    
    #ifdef _WIN32
    int exitCode = _pclose(pipe);
    #else
    int exitCode = pclose(pipe);
    #endif
    
    if (exitCode != 0) {
        throw ClipboardError("Command failed with exit code: " + std::to_string(exitCode));
    }
    
    // Remove trailing newline if present
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    
    return result;
}
