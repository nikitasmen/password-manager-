# Password Manager

A secure, modular password management tool written in C++17 with multiple user interface options.

## Features

- **Secure Local Storage**: All credentials are stored locally in an encrypted JSON format
- **Advanced Encryption**:
  - LFSR (Linear Feedback Shift Register) stream cipher
  - Salt-based encryption for stronger security
  - Base64 encoding for safe storage of binary data
- **Robust JSON Storage System**:
  - Automatic file backups with timestamps
  - RAII-based file handling for resource safety
  - Atomic operations with proper transaction management
  - Optimized file access patterns (open-use-close pattern)
- **Multiple User Interfaces**:
  - Text-based UI (TUI) for terminal environments
  - Modern graphical UI (GUI) using FLTK
  - Shared core API for consistent functionality
- **User-Friendly Features**:
  - Store platform-specific credentials (username/password)
  - View, add, and delete credentials easily
  - Master password protection for all stored data
- **Well-Architected Codebase**:
  - DRY (Don't Repeat Yourself) design principles
  - RAII for resource management
  - Comprehensive error handling
  - Modular component design
  - Helper methods for common operations
  - Standardized dialog management

## Architecture

The project follows a modular architecture with these key components:

- **Core**: Core functionality shared across all interfaces
  - `api.cpp/h`: Main credentials management API
  - `encryption.cpp/h`: LFSR-based encryption with salt support
  - `json_storage.cpp/h`: JSON-based secure storage system
  - `base64.cpp/h`: Base64 encoding/decoding utilities
  - `file_system.cpp/h`: File system operations

- **Terminal UI**: Text-based interface
  - `tui_main.cpp`: Entry point for terminal application
  - `terminal_ui.cpp/h`: Terminal UI components
  - `cli_ui.cpp/h`: Command handling and application controllers

- **Graphical UI**: FLTK-based interface
  - `gui_main.cpp`: Entry point for graphical application
  - `gui.cpp/h`: GUI components and event handlers

- **Configuration**:
  - `GlobalConfig.cpp/h`: Shared configuration settings

## Project Structure

```plaintext
password-manager-/
├── build.sh              # Build script for all components
├── CMakeLists.txt        # CMake configuration
├── src/
│   ├── config/           # Configuration settings
│   │   ├── GlobalConfig.cpp
│   │   └── GlobalConfig.h
│   ├── core/             # Core functionality
│   │   ├── api.cpp
│   │   ├── api.h
│   │   ├── base64.cpp
│   │   ├── base64.h
│   │   ├── encryption.cpp
│   │   ├── encryption.h
│   │   ├── file_system.cpp
│   │   ├── file_system.h
│   │   ├── json_storage.cpp
│   │   ├── json_storage.h
│   │   ├── terminal_ui.cpp
│   │   └── terminal_ui.h
│   ├── cli/              # Command-line interface
│   │   ├── cli_ui.cpp
│   │   └── cli_UI.h
│   ├── gui/              # Graphical user interface
│   │   ├── gui.cpp
│   │   └── gui.h
│   ├── gui_main.cpp      # GUI application entry point
│   └── tui_main.cpp      # Terminal UI application entry point
├── tests/                # Test files
│   └── base64_test.cpp
├── build/                # Build directory (created during build)
│   ├── password_manager      # Terminal UI executable
│   ├── password_manager_gui  # GUI executable
│   └── data/                 # Data storage directory
├── .gitignore
├── LICENSE
└── README.md
```



### Security Enhancements

## Usage

### Graphical User Interface (GUI)

For a user-friendly desktop experience, run the GUI version:

```bash
./build/password_manager_gui
```

The GUI provides:

- Login dialog for master password protection
- List view of all stored platforms
- Add/view credential forms with secure input
- Credential deletion with confirmation
- Clean and modern FLTK-based interface

### Terminal User Interface (TUI)

For a text-based interactive experience, run:

```bash
./build/password_manager
```

This provides a menu-driven interface with these options:

1. Change Master Password
2. Add New Platform Credentials
3. Retrieve Platform Credentials
4. Delete Platform Credentials
5. Show All Stored Platforms

### Command Line Interface

The TUI-based application can be used for various credential operations:

```bash
# Add new credentials
./build/password_manager_gui  # Then use the Add Credential menu option

# Show all stored platforms
./build/password_manager      # Then choose option 5

# Retrieve or delete credentials for specific platforms
# Use the appropriate menu options in either interface
```

## Build Instructions

### Using the Build Script

The easiest way to build the project:

```bash
./build.sh
```

This builds all components. You can customize the build:

```bash
# Build only the GUI version
./build.sh -g

# Build only the terminal UI version
./build.sh -t

# Clean and rebuild everything
./build.sh --clean

# Build with debug symbols
./build.sh --debug
```

Run `./build.sh --help` for all available options.

### Using CMake Directly

```bash
mkdir -p build
cd build
cmake ..
make
```

## Security Features

This password manager implements several security measures:

1. **LFSR Stream Cipher**: Custom encryption using Linear Feedback Shift Register
2. **Salt-Based Security**: Random salt added to encrypted values to prevent rainbow table attacks
3. **Base64 Encoding**: Safe storage of binary data in JSON format
4. **Automatic Backups**: Timestamped backups created before data modifications
5. **Secure File Handling**: Proper file resource management with immediate closing after operations
6. **Memory Management**: Smart pointers to prevent memory leaks
7. **Error Handling**: Comprehensive exception handling throughout the codebase

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Build Script Options

```bash
./build.sh --direct

# Clean and rebuild everything
./build.sh --clean

# Build CLI and terminal UI only
./build.sh --cli --tui
```

For all available options, run:

```bash
./build.sh --help
```

## Dependencies

- C++17 or later
- CMake 3.10+ (for building)
- FLTK 1.3+ (for the GUI version)

## Recent Improvements

The codebase has undergone significant improvements:

- **Optimized File Handling**: Every data operation now properly opens and closes files
- **Enhanced Error Recovery**: Better error handling during file operations
- **Code Refactoring**: Applied DRY principles with helper methods
- **GUI Stability**: Fixed crashes when viewing credentials multiple times
- **Resource Management**: Proper cleanup of FLTK widgets and buffers
- **Standardized Dialogs**: Consistent patterns for all user interactions

## Future Enhancements

Potential future improvements to consider:

- Password strength checker
- Auto-generation of strong passwords
- Import/export functionality
- Configurable encryption options
- Search functionality for large credential sets
- Credential expiration notifications
- Password history tracking
