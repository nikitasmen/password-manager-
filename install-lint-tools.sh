#!/bin/bash

# Install linting tools script for macOS

echo "Installing C++ linting tools..."

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "This script is designed for macOS. Please install tools manually:"
    echo "- clang-format"
    echo "- clang-tidy" 
    echo "- cppcheck"
    exit 1
fi

# Check if Homebrew is installed
if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew not found. Installing Homebrew first..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Add Homebrew to PATH for Apple Silicon Macs
    if [[ $(uname -m) == "arm64" ]]; then
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zshrc
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
fi

echo "Installing tools via Homebrew..."

# Install LLVM (includes clang-format and clang-tidy)
if ! brew list llvm &>/dev/null; then
    echo "Installing LLVM..."
    brew install llvm
else
    echo "LLVM already installed"
fi

# Install cppcheck
if ! brew list cppcheck &>/dev/null; then
    echo "Installing cppcheck..."
    brew install cppcheck
else
    echo "cppcheck already installed"
fi

# Add LLVM tools to PATH
LLVM_PATH="/opt/homebrew/opt/llvm/bin"
if [[ $(uname -m) == "x86_64" ]]; then
    LLVM_PATH="/usr/local/opt/llvm/bin"
fi

echo ""
echo "Installation complete!"
echo ""
echo "To use the tools, add LLVM to your PATH:"
echo "Add this line to your ~/.zshrc or ~/.bash_profile:"
echo "export PATH=\"$LLVM_PATH:\$PATH\""
echo ""
echo "Or run this command now:"
echo "echo 'export PATH=\"$LLVM_PATH:\$PATH\"' >> ~/.zshrc"
echo ""
echo "Then reload your shell or run: source ~/.zshrc"
echo ""
echo "Test the installation with:"
echo "./lint.sh --help"
