#!/bin/bash

# Code Linting Script for Password Manager
# This script runs various linting tools to ensure code quality

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIRS=("src")
HEADER_EXTENSIONS=("h" "hpp")
SOURCE_EXTENSIONS=("cpp" "cc" "c")

# Default settings
RUN_FORMAT=false
RUN_TIDY=false
RUN_CPPCHECK=false
RUN_ALL=false
FIX_ISSUES=false
VERBOSE=false

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -f, --format     Run clang-format"
    echo "  -t, --tidy       Run clang-tidy"
    echo "  -c, --cppcheck   Run cppcheck"
    echo "  -a, --all        Run all linters"
    echo "  -x, --fix        Fix issues automatically where possible"
    echo "  -v, --verbose    Verbose output"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --all                    # Run all linters"
    echo "  $0 --format --fix           # Format code and fix issues"
    echo "  $0 --tidy --verbose         # Run clang-tidy with verbose output"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--format)
            RUN_FORMAT=true
            shift
            ;;
        -t|--tidy)
            RUN_TIDY=true
            shift
            ;;
        -c|--cppcheck)
            RUN_CPPCHECK=true
            shift
            ;;
        -a|--all)
            RUN_ALL=true
            shift
            ;;
        -x|--fix)
            FIX_ISSUES=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option $1"
            print_usage
            exit 1
            ;;
    esac
done

# If no specific tool requested, show help
if [[ "$RUN_FORMAT" == false && "$RUN_TIDY" == false && "$RUN_CPPCHECK" == false && "$RUN_ALL" == false ]]; then
    print_usage
    exit 1
fi

# Set all flags if --all is specified
if [[ "$RUN_ALL" == true ]]; then
    RUN_FORMAT=true
    RUN_TIDY=true
    RUN_CPPCHECK=true
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to find all source files
find_source_files() {
    local files=()
    for dir in "${SOURCE_DIRS[@]}"; do
        if [[ -d "$PROJECT_ROOT/$dir" ]]; then
            for ext in "${SOURCE_EXTENSIONS[@]}" "${HEADER_EXTENSIONS[@]}"; do
                while IFS= read -r -d '' file; do
                    files+=("$file")
                done < <(find "$PROJECT_ROOT/$dir" -name "*.$ext" -print0)
            done
        fi
    done
    printf '%s\n' "${files[@]}"
}

# Function to find C++ source files only
find_cpp_files() {
    local files=()
    for dir in "${SOURCE_DIRS[@]}"; do
        if [[ -d "$PROJECT_ROOT/$dir" ]]; then
            for ext in "${SOURCE_EXTENSIONS[@]}"; do
                while IFS= read -r -d '' file; do
                    files+=("$file")
                done < <(find "$PROJECT_ROOT/$dir" -name "*.$ext" -print0)
            done
        fi
    done
    printf '%s\n' "${files[@]}"
}

# Function to run clang-format
run_clang_format() {
    echo -e "${BLUE}Running clang-format...${NC}"
    
    if ! command_exists clang-format; then
        echo -e "${RED}Error: clang-format not found. Please install it.${NC}"
        echo "macOS: brew install llvm"
        echo "Ubuntu: sudo apt-get install clang-format"
        return 1
    fi
    
    local files
    readarray -t files < <(find_source_files)
    
    if [[ ${#files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No source files found.${NC}"
        return 0
    fi
    
    local format_issues=0
    for file in "${files[@]}"; do
        if [[ "$FIX_ISSUES" == true ]]; then
            if [[ "$VERBOSE" == true ]]; then
                echo "Formatting: $file"
            fi
            clang-format -i "$file"
        else
            local diff_output
            diff_output=$(clang-format "$file" | diff -u "$file" - || true)
            if [[ -n "$diff_output" ]]; then
                echo -e "${YELLOW}Format issues found in: $file${NC}"
                if [[ "$VERBOSE" == true ]]; then
                    echo "$diff_output"
                fi
                ((format_issues++))
            fi
        fi
    done
    
    if [[ "$FIX_ISSUES" == true ]]; then
        echo -e "${GREEN}Code formatting complete.${NC}"
    else
        if [[ $format_issues -eq 0 ]]; then
            echo -e "${GREEN}No formatting issues found.${NC}"
        else
            echo -e "${RED}Found $format_issues files with formatting issues.${NC}"
            echo -e "${YELLOW}Run with --fix to automatically format code.${NC}"
            return 1
        fi
    fi
}

# Function to run clang-tidy
run_clang_tidy() {
    echo -e "${BLUE}Running clang-tidy...${NC}"
    
    if ! command_exists clang-tidy; then
        echo -e "${RED}Error: clang-tidy not found. Please install it.${NC}"
        echo "macOS: brew install llvm"
        echo "Ubuntu: sudo apt-get install clang-tidy"
        return 1
    fi
    
    local files
    readarray -t files < <(find_cpp_files)
    
    if [[ ${#files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No C++ source files found.${NC}"
        return 0
    fi
    
    # Check if compile_commands.json exists
    if [[ ! -f "$PROJECT_ROOT/build/compile_commands.json" ]]; then
        echo -e "${YELLOW}Warning: compile_commands.json not found.${NC}"
        echo "Consider running: mkdir -p build && cd build && cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .."
    fi
    
    local tidy_args=()
    if [[ "$FIX_ISSUES" == true ]]; then
        tidy_args+=(--fix)
    fi
    if [[ -f "$PROJECT_ROOT/build/compile_commands.json" ]]; then
        tidy_args+=(-p "$PROJECT_ROOT/build")
    fi
    
    local issues=0
    for file in "${files[@]}"; do
        if [[ "$VERBOSE" == true ]]; then
            echo "Analyzing: $file"
        fi
        
        local output
        if ! output=$(clang-tidy "${tidy_args[@]}" "$file" 2>&1); then
            echo -e "${YELLOW}Issues found in: $file${NC}"
            if [[ "$VERBOSE" == true ]]; then
                echo "$output"
            fi
            ((issues++))
        fi
    done
    
    if [[ $issues -eq 0 ]]; then
        echo -e "${GREEN}No clang-tidy issues found.${NC}"
    else
        echo -e "${RED}Found issues in $issues files.${NC}"
        if [[ "$FIX_ISSUES" == false ]]; then
            echo -e "${YELLOW}Run with --fix to automatically fix some issues.${NC}"
        fi
        return 1
    fi
}

# Function to run cppcheck
run_cppcheck() {
    echo -e "${BLUE}Running cppcheck...${NC}"
    
    if ! command_exists cppcheck; then
        echo -e "${RED}Error: cppcheck not found. Please install it.${NC}"
        echo "macOS: brew install cppcheck"
        echo "Ubuntu: sudo apt-get install cppcheck"
        return 1
    fi
    
    local cppcheck_args=(
        --enable=all
        --inconclusive
        --std=c++17
        --language=c++
        --force
        --quiet
        --error-exitcode=1
        --suppress=missingIncludeSystem
        --suppress=unusedFunction
        --suppress=unmatchedSuppression
    )
    
    if [[ "$VERBOSE" == true ]]; then
        cppcheck_args+=(--verbose)
    fi
    
    # Add include paths
    for dir in "${SOURCE_DIRS[@]}"; do
        if [[ -d "$PROJECT_ROOT/$dir" ]]; then
            cppcheck_args+=(-I "$PROJECT_ROOT/$dir")
        fi
    done
    
    # Add external include paths
    if [[ -d "/opt/homebrew/include" ]]; then
        cppcheck_args+=(-I "/opt/homebrew/include")
    fi
    if [[ -d "/usr/local/include" ]]; then
        cppcheck_args+=(-I "/usr/local/include")
    fi
    
    # Add source directories
    for dir in "${SOURCE_DIRS[@]}"; do
        if [[ -d "$PROJECT_ROOT/$dir" ]]; then
            cppcheck_args+=("$PROJECT_ROOT/$dir")
        fi
    done
    
    if cppcheck "${cppcheck_args[@]}"; then
        echo -e "${GREEN}No cppcheck issues found.${NC}"
    else
        echo -e "${RED}Cppcheck found issues.${NC}"
        return 1
    fi
}

# Main execution
cd "$PROJECT_ROOT"

echo -e "${BLUE}Password Manager Code Linting${NC}"
echo "=============================="

exit_code=0

if [[ "$RUN_FORMAT" == true ]]; then
    if ! run_clang_format; then
        exit_code=1
    fi
    echo ""
fi

if [[ "$RUN_TIDY" == true ]]; then
    if ! run_clang_tidy; then
        exit_code=1
    fi
    echo ""
fi

if [[ "$RUN_CPPCHECK" == true ]]; then
    if ! run_cppcheck; then
        exit_code=1
    fi
    echo ""
fi

if [[ $exit_code -eq 0 ]]; then
    echo -e "${GREEN}✓ All linting checks passed!${NC}"
else
    echo -e "${RED}✗ Some linting checks failed.${NC}"
    if [[ "$FIX_ISSUES" == false ]]; then
        echo -e "${YELLOW}Tip: Use --fix to automatically fix some issues.${NC}"
    fi
fi

exit $exit_code
