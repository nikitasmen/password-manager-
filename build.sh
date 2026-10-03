#!/usr/bin/env bash
# Password Manager Build Script
# This script builds the unified password manager executable supporting both GUI and CLI modes

# Color codes for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
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

# Package manager: Homebrew on macOS; apt on Debian/Ubuntu, else Homebrew on Linux. Nix (shell.nix) brings everything.
OS=$(uname -s)
PKG=""
if [ "$OS" = Darwin ]; then
    command -v brew &> /dev/null && PKG=brew
elif command -v apt-get &> /dev/null; then
    PKG=apt
elif command -v brew &> /dev/null; then
    PKG=brew
fi
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Function to check dependencies
check_dependencies() {
    echo -e "${BLUE}Checking for required dependencies...${NC}"
    local missing=()

    if [ "$OS" = Darwin ] && ! xcode-select -p &> /dev/null; then
        echo -e "${RED}✗ No C++ compiler. Install the Xcode Command Line Tools, then run this again:${NC}"
        echo "  xcode-select --install"
        exit 1
    fi
    for tool in c++ make cmake fltk-config pkg-config; do
        command -v $tool &> /dev/null || missing+=("$tool")
    done
    # Libraries (headers included): pkg-config on Linux; on macOS curl comes with the system and openssl is keg-only
    if [ "$OS" = Darwin ]; then
        [ "$PKG" = brew ] && ! brew --prefix --installed openssl@3 &> /dev/null && missing+=("openssl")
    elif command -v pkg-config &> /dev/null; then
        for lib in openssl libcurl fontconfig; do
            pkg-config --exists $lib || missing+=("$lib")
        done
    fi
    command -v git &> /dev/null || echo -e "${YELLOW}⚠ git not found: the app's version will show as v0.0${NC}"

    if [ ${#missing[@]} -eq 0 ]; then
        echo -e "${GREEN}✓ Compiler, CMake, FLTK, OpenSSL and curl found${NC}"
        return
    fi

    echo -e "${RED}✗ Missing: ${missing[*]}${NC}"
    local install
    case "$PKG" in
        apt)  install="sudo apt-get install -y build-essential cmake pkg-config git libfltk1.3-dev libssl-dev libcurl4-openssl-dev libfontconfig-dev" ;;
        brew) install="brew install cmake pkg-config fltk openssl@3"
              [ "$OS" = Darwin ] || install="$install gcc curl fontconfig" ;;
        *)    echo "Install a C++17 compiler, make, CMake, pkg-config and the development packages of FLTK 1.3, OpenSSL,"
              echo "libcurl and fontconfig with your package manager, or install Homebrew (https://brew.sh) and run this again."
              exit 1 ;;
    esac
    echo "Install them with:"
    echo "  $install"
    if [ -t 0 ]; then
        read -r -p "Run that now? (y/n) " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            [ "$PKG" = apt ] && sudo apt-get update
            $install || exit 1
            return
        fi
    fi
    exit 1
}

# Function to build with CMake
build_with_cmake() {
    echo -e "${BLUE}Building unified password manager executable...${NC}"
    
    # Configure CMake
    echo -e "${YELLOW}Configuring build with CMake...${NC}"

    # Drop the cache if a cached tool path vanished (e.g. nix store path GC'd after a toolchain bump)
    for var in CMAKE_CXX_COMPILER CMAKE_MAKE_PROGRAM; do
        cached=$(sed -n "s/^$var:[A-Z]*=//p" CMakeCache.txt 2>/dev/null)
        if [ -n "$cached" ] && [ ! -x "$cached" ]; then
            echo -e "${YELLOW}Cached $var $cached is gone, resetting CMake cache${NC}"
            rm -rf CMakeCache.txt CMakeFiles
            break
        fi
    done

    local args=("-DCMAKE_BUILD_TYPE=$([ "$DEBUG" = true ] && echo Debug || echo Release)")
    if [ "$PKG" = brew ]; then
        # Homebrew's prefix (/opt/homebrew on Apple Silicon) isn't searched by default, and openssl@3 is keg-only
        args+=(-DCMAKE_PREFIX_PATH="$(brew --prefix)" -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)")
    fi
    cmake "${args[@]}" .

    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ CMake configuration failed${NC}"
        exit 1
    fi

    # Build the project
    echo -e "${YELLOW}Building password_manager executable...${NC}"
    
    if [ "$DEBUG" = true ]; then
        make VERBOSE=1 -j"$JOBS"
    else
        make -j"$JOBS"
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ Build failed${NC}"
        exit 1
    fi
    
    # Build and run tests if requested
    if [ "$TESTS" = true ]; then
        echo -e "${YELLOW}Building and running tests...${NC}"
        make -j"$JOBS" base64_test vault_test
        echo -e "${YELLOW}Running base64 tests...${NC}"
        ./base64_test || exit 1
        echo -e "${YELLOW}Running vault tests...${NC}"
        ./vault_test || exit 1
    fi
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
