# Enhanced Password Manager

A secure, lightweight password management tool written in C++ with advanced security features.

## Features

- **Local Storage**: All passwords are stored locally on your machine
- **Enhanced Encryption**:
  - LFSR (Linear Feedback Shift Register) based encryption
  - Salt-based security for improved resistance to attacks
  - Enhanced error handling and recovery mechanisms
- **Multiple Interfaces**:  
  - Command-line interface (CLI) for scripting and automation
  - Interactive terminal UI for console-based interaction
  - Graphical user interface (GUI) for user-friendly desktop experience
- **Password Management**:
  - Store credentials (username/password) for different platforms
  - Retrieve and copy credentials to clipboard
  - Delete credentials when no longer needed
  - List all platforms with stored credentials
- **Enhanced Security Features**:
  - Path sanitization to prevent traversal attacks
  - Automatic backup of credential files
  - Robust exception handling
  - Secure credential storage with salt-based encryption

## Architecture

The project is organized into three main components:

- **Core**: Provides the fundamental functionality
  - Secure encryption/decryption with salt-based protection
  - File system operations with path security
  - Credential management with error handling
  - User interface abstractions
- **UI**:  
  - Terminal-based interactive user interface
  - Graphical user interface using FLTK
  - Improved error reporting and user feedback
- **CLI**: Command-line interface for scripting and automation
  - Enhanced command parsing
  - Better error handling and status reporting
  - Support for batch operations

## Project Structure

```plaintext
password-manager-/
├── GlobalConfig.cpp       # Global configuration variables
├── GlobalConfig.h         # Header for global configuration
├── passman.cpp            # Main application entry point
├── src/
│   ├── mainApi.cpp        # API main function
│   ├── mainUi.cpp         # UI main function
│   ├── cli/               # Command Line Interface
│   │   ├── cli_api.cpp    # CLI API implementation
│   │   ├── cli_api.h      # CLI API header
│   │   ├── cli_ui.cpp     # CLI UI implementation
│   │   └── cli_ui.h       # CLI UI header
│   ├── core/              # Core functionality
│   │   ├── api.cpp        # Core API implementation
│   │   ├── api.h          # Core API header
│   │   ├── encryption.cpp # Encryption functionality
│   │   ├── encryption.h   # Encryption header
│   │   ├── fileSys.cpp    # File system operations
│   │   ├── fileSys.h      # File system header
│   │   ├── ui.cpp         # Core UI implementation
│   │   └── ui.h           # Core UI header
│   └── data/              # Data management
│       ├── credentials    # Credentials storage
│       ├── data.cpp       # Data handling implementation
│       └── loginPassword  # Master password storage
├── .gitignore
├── LICENSE
└── README.md
```

## Usage

### Graphical User Interface

For a more user-friendly experience, run the GUI version:

```bash
./password_manager_gui
```

The GUI provides:

- Login dialog for master password
- List view of all stored platforms
- Forms for adding/viewing credentials
- Ability to delete credentials

### Interactive Terminal UI

Run the terminal UI version without arguments:

```bash
./password_manager
```

### Command-line Interface

```bash
./cli_api <option> <userPassword> [values...]
```

Available options:

- `-h`, `--help` - Show help message and available commands
- `-a`, `--add <password> <platform> <username> <platform_password>` - Add new credentials
- `-s`, `--show <password>` - List all stored platforms
- `-g`, `--get <password> <platform>` - Show credentials for specified platform
- `-d`, `--delete <password> <platform>` - Delete credentials for specified platform
- `-p`, `--password <old_password> <new_password>` - Change master password

### Security Enhancements

This improved version includes several security enhancements:

1. **Salt-Based Encryption**: Adds random data to each encrypted value, making dictionary attacks significantly harder
2. **Path Sanitization**: Prevents path traversal attacks by sanitizing platform names used in file paths
3. **File System Security**: Better handling of file system operations with proper error checking
4. **Backup System**: Automatically creates backups of credential files before modifying them
5. **Error Handling**: Comprehensive exception handling throughout the codebase
6. **Memory Management**: Improved memory handling to prevent leaks and buffer overflows

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
- `-c <platform>` - Return and copy record for the specified platform

### Examples

```bash
# Display help information
./cli_api myMasterPassword -h

# Add new credentials
./cli_api myMasterPassword -a github johndoe password123

# Show all stored platforms
./cli_api myMasterPassword -s

# Retrieve credentials for a specific platform
./cli_api myMasterPassword -c github
```

## 🔧 Build Instructions

### Using the Unified Build Script

The easiest way to build all versions:

```bash
./build.sh
```

This will create all three executables in the `build` directory.

You can customize your build with various options:

```bash
# Build only the GUI version
./build.sh --gui

# Build without CMake (direct compilation)
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

### Option 1: Simple Compile

```bash
# Compile the main UI version
g++ passman.cpp GlobalConfig.cpp src/core/*.cpp src/data/data.cpp -o password-manager -std=c++17

# Compile the CLI version
g++ src/cli/cli_api.cpp src/core/*.cpp GlobalConfig.cpp -o cli_api -std=c++17
```

### Option 2: Using CMake

```bash
mkdir build
cd build
cmake ..
make
```

## 🔒 Security Notes

- Passwords are encrypted using an LFSR-based algorithm
- All data is stored locally - no internet connection required
- The master password is used for encryption/decryption
- For actual production use, consider implementing additional security measures

## Dependencies

- C++17 or later
- CMake 3.10+ (for building)
- FLTK 1.3+ (for the GUI version)
- For clipboard functionality on Linux: xclip or xsel

## 📌 Future Improvements

- Enhanced encryption algorithms
- Improved user authentication
- Better error handling and input validation
- Graphical user interface
- Password strength checker
- Auto-generation of strong passwords

## 🤝 Contributing

Pull requests are welcome. Here's how to contribute:

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add feature"`
4. Push to your fork: `git push origin feature/my-feature`
5. Open a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
