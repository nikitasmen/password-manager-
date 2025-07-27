# Password Manager

A secure, modular password management tool written in C++17 with multiple user interface options and robust encryption support.

## Features

- **Secure Local Storage**: All credentials are stored locally in an encrypted JSON format
- **Advanced Encryption System**:
  - Multiple encryption backends (AES, LFSR)
  - Pluggable encryption architecture with factory pattern
  - Salt-based encryption for stronger security
  - Support for encryption algorithm migration
- **Robust Storage System**:
  - Automatic file backups with timestamps
  - RAII-based resource management
  - Transaction-safe operations
  - Optimized file access patterns
- **Multiple User Interfaces**:
  - Text-based UI (TUI) for terminal environments
  - Modern graphical UI (GUI) using FLTK
  - Shared core API for consistent functionality
- **User Management**:
  - Secure master password protection
  - Password strength validation
  - Secure credential storage and retrieval
- **Well-Architected Codebase**:
  - Clean separation of concerns
  - Factory pattern for encryption backends
  - Comprehensive error handling
  - Modular component design
  - Unit test coverage
  - Modern C++17 features

## Architecture

The project follows a modular architecture with these key components:

- **Core**: Core functionality shared across all interfaces
  - `api.cpp/h`: Main credentials management API
  - `json_storage.cpp/h`: JSON-based credential storage
  - `file_system.cpp/h`: File system operations
  - `UIManager`: Interface for UI components
  - `ConfigManager`: Application configuration

- **Crypto**: Encryption subsystem
  - `encryption_interface.h`: Base interface for all encryption backends
  - `aes_encryption.cpp/h`: AES encryption implementation
  - `lfsr_encryption.cpp/h`: LFSR stream cipher implementation
  - `salted_encryption.h`: Salt-based encryption wrapper
  - `encryption_factory.cpp/h`: Factory for creating encryption instances
  - `cipher_context_raii.cpp/h`: RAII wrapper for encryption contexts

- **Terminal UI**: Text-based interface
  - `tui_main.cpp`: Entry point for terminal application
  - `terminal_ui.cpp/h`: Terminal UI components
  - `cli_ui.cpp/h`: Command handling and application controllers

- **Graphical UI**: FLTK-based interface
  - `gui_main.cpp`: Entry point for graphical application
  - `gui.cpp/h`: GUI components and event handlers
  - `dialogs/`: Various dialog implementations

- **Configuration**:
  - `GlobalConfig.cpp/h`: Shared configuration settings
  - `MigrationHelper.cpp/h`: Handles data migration between versions

## Project Structure

```plaintext
password-manager-/
├── build.sh              # Build script for all components
├── CMakeLists.txt        # CMake configuration
├── src/
│   ├── cli/              # Command-line interface
│   │   ├── cli_ui.cpp
│   │   └── cli_UI.h
│   ├── config/           # Configuration settings
│   │   ├── GlobalConfig.cpp
│   │   ├── GlobalConfig.h
│   │   ├── MigrationHelper.cpp
│   │   └── MigrationHelper.h
│   ├── core/             # Core functionality
│   │   ├── api.cpp
│   │   ├── api.h
│   │   ├── json_storage.cpp
│   │   ├── json_storage.h
│   │   ├── UIManager.cpp
│   │   ├── UIManager.h
│   │   └── file_system.cpp
│   ├── crypto/           # Encryption subsystem
│   │   ├── aes_encryption.cpp
│   │   ├── aes_encryption.h
│   │   ├── cipher_context_raii.cpp
│   │   ├── cipher_context_raii.h
│   │   ├── encryption_factory.cpp
│   │   ├── encryption_factory.h
│   │   ├── encryption_interface.h
│   │   ├── encryption_type.h
│   │   ├── lfsr_encryption.cpp
│   │   ├── lfsr_encryption.h
│   │   └── salted_encryption.h
│   ├── gui/              # Graphical user interface
│   │   ├── dialogs/      # Dialog implementations
│   │   ├── gui.cpp
│   │   └── gui.h
│   ├── gui_main.cpp      # GUI application entry point
│   ├── tui_main.cpp      # Terminal UI application entry point
│   └── utils/            # Utility functions
│       └── string_utils.cpp
├── tests/                # Test files
│   ├── unit/            # Unit tests
│   └── integration/     # Integration tests
├── build/               # Build directory (created during build)
│   ├── password_manager      # Terminal UI executable
│   ├── password_manager_gui  # GUI executable
│   └── data/            # Data storage directory
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

This password manager implements multiple layers of security:

1. **Multiple Encryption Backends**:
   - AES-256 for strong cryptographic protection
   - LFSR (Linear Feedback Shift Register) for lightweight encryption
   - Pluggable architecture for future encryption algorithms

2. **Secure Key Management**:
   - Master password hashing with salt
   - Secure key derivation
   - Encryption context management with RAII

3. **Data Protection**:
   - Salt-based encryption to prevent rainbow table attacks
   - Secure memory handling
   - Automatic data migration between encryption types

4. **Operational Security**:
   - Automatic backups before critical operations
   - Secure file handling
   - Transaction-safe storage operations
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
