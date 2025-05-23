# Password Manager

A secure, lightweight password management tool written in C++.

## Features

- **Local Storage**: All passwords are stored locally on your machine
- **Strong Encryption**: Uses LFSR (Linear Feedback Shift Register) encryption
- **Multiple Interfaces**: Both command-line interface (CLI) and interactive UI
- **Password Management**:
  - Store credentials (username/password) for different platforms
  - Retrieve and copy credentials to clipboard
  - Delete credentials when no longer needed
  - List all platforms with stored credentials

## Architecture

The project is organized into three main components:

- **Core**: Provides the fundamental functionality
  - Encryption/decryption
  - File system operations
  - Credential management
- **UI**: Interactive user interface for managing passwords
- **CLI**: Command-line interface for scripting and automation

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

### Interactive UI

Run the application without arguments to use the interactive interface:

```bash
./password-manager
```

### Command-line Interface

```bash
./cli_api <userPassword> <option> [values...]
```

Available options:

- `-h` - Show manual and available commands
- `-a <platform> <user> <pass>` - Add password for a specific platform
- `-s` - Show all records
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
