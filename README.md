# Password Manager

A secure, cross-platform password management tool written in C++17 with unified executable supporting both GUI and CLI modes, advanced encryption, and automatic update capabilities.

## Features

- **Unified Application**: Single executable that can run in both GUI and CLI modes
- **Secure Local Storage**: All credentials are stored locally in encrypted JSON format with automatic backups
- **Advanced Encryption System**:
  - Multiple encryption backends (AES-256, LFSR, RSA)
  - Pluggable encryption architecture with factory pattern
  - Salt-based encryption for enhanced security
  - Seamless encryption algorithm migration
- **Robust Storage System**:
  - Automatic file backups with timestamps
  - RAII-based resource management
  - Transaction-safe operations with rollback capability
  - DRY principles with common utility modules
- **Multiple User Interfaces**:
  - Modern graphical UI (GUI) using FLTK with update dialogs
  - Text-based UI (TUI) for terminal environments
  - Shared core API for consistent functionality
- **Auto-Update System**:
  - GitHub integration for checking latest releases
  - Automatic download and installation with progress tracking
  - Cross-platform update support (Windows, macOS, Linux)
  - Secure update process with backup and rollback
- **Security Enhancements**:
  - Secure clipboard operations with auto-clear
  - Command injection prevention in system calls
  - Memory-safe operations with smart pointers
  - Comprehensive error handling and logging
- **Configuration Management**:
  - File-based configuration system (.config)
  - Configurable GitHub repository settings
  - Flexible UI mode selection
  - User-customizable security settings

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
password-manager/
├── build.sh                       # Build script for all components
├── CMakeLists.txt                 # CMake configuration
├── password_manager               # Unified executable (generated)
├── data/                          # Application data directory
│   └── secure_storage.json        # Encrypted credentials database
├── include/                       # Third-party headers
│   └── nlohmann/
│       └── json.hpp
├── src/
│   ├── main.cpp                   # Unified application entry point
│   ├── gui_main.cpp               # GUI mode implementation
│   ├── tui_main.cpp               # Terminal UI mode implementation
│   ├── cli/                       # Command-line interface components
│   │   ├── TerminalUIManager.cpp
│   │   └── TerminalUIManager.h
│   ├── config/                    # Configuration settings
│   │   ├── GlobalConfig.cpp
│   │   ├── GlobalConfig.h
│   │   ├── MigrationHelper.cpp
│   │   └── MigrationHelper.h
│   ├── core/                      # Core functionality
│   │   ├── api.cpp
│   │   ├── api.h
│   │   ├── base64.cpp
│   │   ├── base64.h
│   │   ├── clipboard.cpp
│   │   ├── clipboard.h
│   │   ├── credential_data.h
│   │   ├── encryption.cpp
│   │   ├── encryption.h
│   │   ├── json_storage.cpp
│   │   ├── json_storage.h
│   │   ├── terminal_ui.cpp
│   │   ├── terminal_ui.h
│   │   ├── UIManager.cpp
│   │   ├── UIManager.h
│   │   ├── UIManagerFactory.cpp
│   │   └── UIManagerFactory.h
│   ├── crypto/                    # Encryption subsystem
│   │   ├── aes_encryption.cpp
│   │   ├── aes_encryption.h
│   │   ├── cipher_context_raii.cpp
│   │   ├── cipher_context_raii.h
│   │   ├── encryption_factory.cpp
│   │   ├── encryption_factory.h
│   │   ├── encryption_interface.h
│   │   ├── lfsr_encryption.cpp
│   │   ├── lfsr_encryption.h
│   │   ├── rsa_encryption.cpp
│   │   └── rsa_encryption.h
│   ├── gui/                       # Graphical user interface
│   │   ├── fl_main.cpp
│   │   ├── password_gui.cpp
│   │   ├── password_gui.h
│   │   └── [other GUI files]
│   ├── updater/                   # Auto-update system
│   │   ├── AppUpdater.cpp
│   │   ├── AppUpdater.h
│   │   ├── GitHubAPI.cpp
│   │   ├── GitHubAPI.h
│   │   ├── system_utils.cpp
│   │   └── system_utils.h
│   └── utils/                     # Common utilities (DRY compliance)
│       ├── filesystem_utils.cpp
│       ├── filesystem_utils.h
│       ├── error_utils.cpp
│       ├── error_utils.h
│       ├── backup_utils.cpp
│       └── backup_utils.h
├── tests/                         # Test files
│   └── base64_test.cpp
├── .gitignore
├── LICENSE
└── README.md
```



### Security Enhancements

## Usage

The application provides a unified executable with both GUI and CLI modes.

### Command Line Arguments

```bash
# Run in GUI mode (default)
./password_manager
./password_manager -g
./password_manager --gui

# Run in CLI/Terminal mode
./password_manager -t
./password_manager --terminal

# Show help
./password_manager --help
```

### Graphical User Interface (GUI)

The GUI mode provides a user-friendly desktop experience:

```bash
./password_manager -g
```

GUI features include:
- Modern FLTK-based interface with dialogs
- Login dialog for master password protection
- List view of all stored platforms
- Add/view credential forms with secure input
- Credential deletion with confirmation
- Auto-update notifications and progress dialogs

### Terminal User Interface (CLI)

For a text-based interactive experience:

```bash
./password_manager -t
```

CLI features include:
- Menu-driven interface with numbered options
- Secure master password handling
- Interactive credential management
- Platform listing and search
- Command injection prevention

Available CLI operations:
1. Change Master Password
2. Add New Platform Credentials
3. Retrieve Platform Credentials
4. Delete Platform Credentials
5. Show All Stored Platforms

## Build Instructions

### Using the Build Script

The easiest way to build the unified executable:

```bash
./build.sh
```

This creates the single `password_manager` executable with both GUI and CLI modes.

### Using CMake Directly

```bash
mkdir -p build
cd build
cmake ..
make
```

This produces a single `password_manager` executable that can run in either GUI or CLI mode based on command-line arguments.

### Build Output

After building, you'll have:
- `password_manager` - Unified executable supporting both modes
- Test executables (if enabled)
- Data directory structure

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
- **Auto-Update System**: Added GitHub integration for automatic updates

## Auto-Update System

The GUI version includes a built-in update system that allows you to:

- **Check for Updates**: Access via the Help menu → Check for Updates
- **Automatic Download**: Download and install updates with progress reporting
- **Version Comparison**: Compare current version with latest GitHub release
- **Release Notes**: View what's new in each version
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Secure Updates**: Downloads from official GitHub releases

### How to Use Updates

1. Open the GUI application (`./password_manager -g`)
2. Go to Help → Check for Updates
3. Click "Check for Updates" to see if a new version is available
4. If an update is found, click "Download Update" to install it
5. Restart the application when prompted

The updater will:

- Download the latest release from the GitHub repository
- Create a backup of your current version
- Replace the executable with the new version
- Maintain all your existing data and settings

## Architecture Improvements

This codebase follows DRY (Don't Repeat Yourself) principles with:

- **Common Utilities**: Shared filesystem, error handling, and backup utilities in `src/utils/`
- **Unified Architecture**: Single executable supporting both GUI and CLI modes
- **Modular Design**: Factory patterns for encryption backends and UI managers
- **Resource Management**: RAII patterns for secure resource handling
- **Error Consistency**: Standardized error logging and exception handling

## Future Enhancements

Potential future improvements to consider:

- Password strength checker with entropy analysis
- Auto-generation of strong passwords with customizable policies
- Import/export functionality for credential migration
- Configurable encryption options with user selection
- Search functionality for large credential sets
- Credential expiration notifications and alerts
- Password history tracking and audit logs
- Multi-factor authentication support
