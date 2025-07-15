#!/bin/bash

# Password Manager Build Script
# This script provides a unified way to build all components of the password manager

# Color codes for pretty output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
USE_CMAKE=true
BUILD_ALL=true
BUILD_CLI=false
BUILD_TUI=false
BUILD_GUI=false
CLEAN=false

# Function to print usage information
print_usage() {
    echo -e "${BLUE}Password Manager Build Script${NC}"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -d, --direct        Use direct compilation instead of CMake"
    echo "  -c, --cli           Build only the CLI version"
    echo "  -t, --tui           Build only the terminal UI version"
    echo "  -g, --gui           Build only the GUI version"
    echo "  --clean             Clean build directories before building"
    echo ""
    echo "Examples:"
    echo "  $0                  Build all versions using CMake (default)"
    echo "  $0 -g -d            Build only GUI version with direct compilation"
    echo "  $0 -c -t            Build CLI and terminal UI versions with CMake"
    echo "  $0 --clean          Clean and rebuild all versions"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        -d|--direct)
            USE_CMAKE=false
            shift
            ;;
        -c|--cli)
            BUILD_CLI=true
            BUILD_ALL=false
            shift
            ;;
        -t|--tui)
            BUILD_TUI=true
            BUILD_ALL=false
            shift
            ;;
        -g|--gui)
            BUILD_GUI=true
            BUILD_ALL=false
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        *)
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# Check build targets
if [ "$BUILD_ALL" = false ] && [ "$BUILD_CLI" = false ] && [ "$BUILD_TUI" = false ] && [ "$BUILD_GUI" = false ]; then
    echo -e "${RED}Error: No build targets specified. Please select at least one target to build.${NC}"
    print_usage
    exit 1
fi

# If BUILD_ALL is true, set all individual build flags to true
if [ "$BUILD_ALL" = true ]; then
    BUILD_CLI=true
    BUILD_TUI=true
    BUILD_GUI=true
fi

# Clean build directories if requested
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning build directories...${NC}"
    rm -rf build build-make direct-build gui-build simple-build
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

    # Check for CMake if needed
    if [ "$USE_CMAKE" = true ]; then
        if ! command -v cmake &> /dev/null; then
            echo -e "${RED}✗ CMake is not installed but required for this build method.${NC}"
            echo "Would you like to install it with Homebrew? (y/n)"
            read -r install_cmake
            if [[ "$install_cmake" =~ ^[Yy]$ ]]; then
                brew install cmake
            else
                echo -e "${RED}Cannot continue without CMake.${NC}"
                echo "Try running with -d option for direct compilation instead."
                exit 1
            fi
        else
            echo -e "${GREEN}✓ CMake found: $(cmake --version | head -n 1)${NC}"
        fi
    fi

    # Check for FLTK if building GUI
    if [ "$BUILD_GUI" = true ]; then
        if ! command -v fltk-config &> /dev/null; then
            echo -e "${RED}✗ FLTK not found but required for GUI version.${NC}"
            echo "Would you like to install it with Homebrew? (y/n)"
            read -r install_fltk
            if [[ "$install_fltk" =~ ^[Yy]$ ]]; then
                brew install fltk
            else
                echo -e "${YELLOW}Warning: GUI version won't be built.${NC}"
                BUILD_GUI=false
            fi
        else
            echo -e "${GREEN}✓ FLTK found: $(fltk-config --version)${NC}"
        fi
    fi
}

# Function to build with CMake
build_with_cmake() {
    echo -e "${BLUE}Building with CMake...${NC}"
    mkdir -p build
    cd build

    # Configure
    echo -e "${YELLOW}Configuring build with CMake...${NC}"
    cmake ..

    # Build targets
    echo -e "${YELLOW}Building project...${NC}"
    
    if [ "$BUILD_ALL" = true ]; then
        make -j4
    else
        targets=""
        if [ "$BUILD_CLI" = true ]; then
            targets="$targets cli_api"
        fi
        if [ "$BUILD_TUI" = true ]; then
            targets="$targets password_manager"
        fi
        if [ "$BUILD_GUI" = true ]; then
            targets="$targets password_manager_gui"
        fi
        
        if [ -n "$targets" ]; then
            make -j4 $targets
        fi
    fi
    
    cd ..
}

# Function for direct compilation
build_direct() {
    echo -e "${BLUE}Building with direct compilation...${NC}"
    mkdir -p direct-build
    
    # Build CLI
    if [ "$BUILD_CLI" = true ]; then
        echo -e "${YELLOW}Compiling CLI version...${NC}"
        echo -e "${RED}Error: Direct compilation is no longer supported.${NC}"
        echo -e "${RED}Please use CMake to build the project.${NC}"
        exit 1
    fi
    
    # Build terminal UI
    if [ "$BUILD_TUI" = true ]; then
        echo -e "${YELLOW}Compiling terminal UI version...${NC}"
        echo -e "${RED}Error: Direct compilation is no longer supported.${NC}"
        echo -e "${RED}Please use CMake to build the project.${NC}"
        exit 1
            src/core/api.cpp src/core/encryption.cpp src/core/fileSys.cpp \
            src/core/ui.cpp src/data/data.cpp GlobalConfig.cpp
    fi
    
    # Build GUI
    if [ "$BUILD_GUI" = true ]; then
        echo -e "${YELLOW}Compiling GUI version...${NC}"
        c++ -std=c++17 $(fltk-config --cxxflags) -I. -o direct-build/password_manager_gui \
            src/mainGui.cpp src/gui/gui.cpp src/core/api.cpp src/core/encryption.cpp \
            src/core/fileSys.cpp src/core/ui.cpp src/data/data.cpp GlobalConfig.cpp \
            $(fltk-config --ldflags)
    fi
}

# Function to print results
print_results() {
    echo -e "${BLUE}======================================================================${NC}"
    echo -e "${GREEN}Build complete! Executables created:${NC}"
    
    local build_dir=""
    if [ "$USE_CMAKE" = true ]; then
        build_dir="build"
    else
        build_dir="direct-build"
    fi
    
    if [ "$BUILD_CLI" = true ] && [ -f "$build_dir/cli_api" ]; then
        echo -e "${GREEN}✓ CLI version:${NC} ./$build_dir/cli_api"
    elif [ "$BUILD_CLI" = true ]; then
        echo -e "${RED}✗ CLI version build failed${NC}"
    fi
    
    if [ "$BUILD_TUI" = true ] && [ -f "$build_dir/password_manager" ]; then
        echo -e "${GREEN}✓ Terminal UI:${NC} ./$build_dir/password_manager"
    elif [ "$BUILD_TUI" = true ]; then
        echo -e "${RED}✗ Terminal UI build failed${NC}"
    fi
    
    if [ "$BUILD_GUI" = true ] && [ -f "$build_dir/password_manager_gui" ]; then
        echo -e "${GREEN}✓ GUI version:${NC} ./$build_dir/password_manager_gui"
    elif [ "$BUILD_GUI" = true ]; then
        echo -e "${RED}✗ GUI version build failed${NC}"
    fi
    
    echo -e "${BLUE}======================================================================${NC}"
}

# Main execution flow
check_dependencies

# Execute the appropriate build method
if [ "$USE_CMAKE" = true ]; then
    build_with_cmake
else
    build_direct
fi

# Show results
print_results

exit 0
