#!/bin/bash

# Password Manager Build Script
# This script builds the unified password manager executable supporting both GUI and CLI modes

# Color codes for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
USE_CMAKE=true
CLEAN=false
DEBUG=false
TESTS=false

# Function to print usage information
print_usage() {
    echo -e "${BLUE}Password Manager Build Script${NC}"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  --clean             Clean build directories before building"
    echo "  --debug             Build with debug symbols and verbose output"
    echo "  --tests             Build and run tests"
    echo ""
    echo "About:"
    echo "  This script builds a unified password_manager executable that supports"
    echo "  both GUI and CLI modes through command-line arguments:"
    echo "    ./password_manager -g    (GUI mode)"
    echo "    ./password_manager -t    (CLI mode)"
    echo "    ./password_manager --help"
    echo ""
    echo "Examples:"
    echo "  $0                  Build the password manager (default)"
    echo "  $0 --clean          Clean and rebuild"
    echo "  $0 --debug          Build with debug information"
    echo "  $0 --tests          Build and run tests"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        --tests)
            TESTS=true
            shift
            ;;
        *)
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# Clean build directories if requested
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning build directories...${NC}"
    rm -rf build CMakeCache.txt CMakeFiles cmake_install.cmake Makefile
    echo -e "${GREEN}✓ Build directories cleaned${NC}"
fi

# Function to check dependencies
check_dependencies() {
    echo -e "${BLUE}Checking for required dependencies...${NC}"

    # Check for C++ compiler
    if ! command -v c++ &> /dev/null; then
        echo -e "${RED}✗ C++ compiler not found. Please install Xcode Command Line Tools with:${NC}"
        echo "  xcode-select --install"
        exit 1
    else
        echo -e "${GREEN}✓ C++ compiler found: $(c++ --version | head -n 1)${NC}"
    fi

    # Check for CMake
    if ! command -v cmake &> /dev/null; then
        echo -e "${RED}✗ CMake is not installed but required for building.${NC}"
        echo "Would you like to install it with Homebrew? (y/n)"
        read -r install_cmake
        if [[ "$install_cmake" =~ ^[Yy]$ ]]; then
            brew install cmake
        else
            echo -e "${RED}Cannot continue without CMake.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}✓ CMake found: $(cmake --version | head -n 1)${NC}"
    fi

    # Check for FLTK (required for GUI mode)
    if ! command -v fltk-config &> /dev/null; then
        echo -e "${RED}✗ FLTK not found but required for GUI functionality.${NC}"
        echo "Would you like to install it with Homebrew? (y/n)"
        read -r install_fltk
        if [[ "$install_fltk" =~ ^[Yy]$ ]]; then
            brew install fltk
        else
            echo -e "${RED}Cannot continue without FLTK.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}✓ FLTK found: $(fltk-config --version)${NC}"
    fi

    # Check for OpenSSL (required for encryption)
    if ! command -v openssl &> /dev/null; then
        echo -e "${YELLOW}⚠ OpenSSL not found in PATH, but may be available via pkg-config${NC}"
    else
        echo -e "${GREEN}✓ OpenSSL found: $(openssl version)${NC}"
    fi

    # Check for pkg-config
    if ! command -v pkg-config &> /dev/null; then
        echo -e "${YELLOW}⚠ pkg-config not found, may need manual library configuration${NC}"
    else
        echo -e "${GREEN}✓ pkg-config found${NC}"
    fi
}

# Function to build with CMake
build_with_cmake() {
    echo -e "${BLUE}Building unified password manager executable...${NC}"
    
    # Configure CMake
    echo -e "${YELLOW}Configuring build with CMake...${NC}"
    
    if [ "$DEBUG" = true ]; then
        cmake -DCMAKE_BUILD_TYPE=Debug .
    else
        cmake -DCMAKE_BUILD_TYPE=Release .
    fi

    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ CMake configuration failed${NC}"
        exit 1
    fi

    # Build the project
    echo -e "${YELLOW}Building password_manager executable...${NC}"
    
    if [ "$DEBUG" = true ]; then
        make VERBOSE=1 -j4
    else
        make -j4
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ Build failed${NC}"
        exit 1
    fi
    
    # Build and run tests if requested
    if [ "$TESTS" = true ]; then
        echo -e "${YELLOW}Building and running tests...${NC}"
        make base64_test
        if [ -f "./base64_test" ]; then
            echo -e "${YELLOW}Running base64 tests...${NC}"
            ./base64_test
        fi
    fi
}

# Function for direct compilation (deprecated)
build_direct() {
    echo -e "${RED}Error: Direct compilation is no longer supported.${NC}"
    echo -e "${RED}This project now requires CMake to build properly.${NC}"
    echo -e "${YELLOW}Please use CMake to build the unified executable.${NC}"
    exit 1
}

# Function to print results
print_results() {
    echo -e "${BLUE}======================================================================${NC}"
    
    if [ -f "./password_manager" ]; then
        echo -e "${GREEN}✓ Build successful! Unified executable created:${NC}"
        echo -e "${GREEN}  ./password_manager${NC}"
        echo ""
        echo -e "${BLUE}Usage:${NC}"
        echo -e "  ${YELLOW}./password_manager -g${NC}        # Run in GUI mode"
        echo -e "  ${YELLOW}./password_manager -t${NC}        # Run in CLI mode"
        echo -e "  ${YELLOW}./password_manager --help${NC}    # Show help"
        echo ""
        
        # Show file size and permissions
        local size=$(ls -lh ./password_manager | awk '{print $5}')
        echo -e "${BLUE}Executable details:${NC}"
        echo -e "  Size: $size"
        echo -e "  Permissions: $(ls -l ./password_manager | awk '{print $1}')"
        
        # Check if tests were built
        if [ "$TESTS" = true ] && [ -f "./base64_test" ]; then
            echo -e "${GREEN}✓ Tests built and executed successfully${NC}"
        fi
    else
        echo -e "${RED}✗ Build failed - executable not found${NC}"
        echo -e "${RED}Check the build output above for errors${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}======================================================================${NC}"
}

# Main execution flow
echo -e "${BLUE}Password Manager Build Script${NC}"
echo -e "${BLUE}Building unified executable with GUI and CLI modes${NC}"
echo ""

check_dependencies
build_with_cmake
print_results

echo -e "${GREEN}Build completed successfully!${NC}"
exit 0
