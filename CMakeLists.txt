cmake_minimum_required(VERSION 3.10)
project(password_manager)

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Export compile commands for clang-tidy
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# JSON library: exactly one copy. json 3.11+ puts its version in symbol names, so objects built against two
# different headers don't link. Use the installed package (nix-shell provides it), else download a header once.
find_package(nlohmann_json 3.11 CONFIG QUIET)
if(nlohmann_json_FOUND)
    message(STATUS "Using nlohmann_json ${nlohmann_json_VERSION} from ${nlohmann_json_DIR}")
    set(JSON_LIB nlohmann_json::nlohmann_json)
    set(JSON_INCLUDE_DIR "")
else()
    set(JSON_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
    if(NOT EXISTS ${JSON_INCLUDE_DIR}/nlohmann/json.hpp)
        file(DOWNLOAD
            https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
            ${JSON_INCLUDE_DIR}/nlohmann/json.hpp.part
            STATUS json_status SHOW_PROGRESS)
        list(GET json_status 0 json_rc)
        if(NOT json_rc EQUAL 0)
            file(REMOVE ${JSON_INCLUDE_DIR}/nlohmann/json.hpp.part)
            message(FATAL_ERROR "Downloading json.hpp failed (${json_status}); needs network once, or install nlohmann_json")
        endif()
        file(RENAME ${JSON_INCLUDE_DIR}/nlohmann/json.hpp.part ${JSON_INCLUDE_DIR}/nlohmann/json.hpp)
    endif()
    include_directories(${JSON_INCLUDE_DIR})
endif()

# --- Find FLTK ---
find_package(FLTK REQUIRED)

# --- Find OpenSSL for AES encryption ---
find_package(OpenSSL REQUIRED)

# --- Find CURL for HTTP requests (used by updater) ---
if(NOT WIN32)
    find_package(CURL REQUIRED)
    if(CURL_FOUND)
        message(STATUS "Found CURL: ${CURL_LIBRARIES}")
        message(STATUS "CURL include directories: ${CURL_INCLUDE_DIRS}")
    else()
        message(FATAL_ERROR "CURL not found but required for updater functionality")
    endif()
endif()

# --- Source files ---
set(CORE_SOURCES
    src/core/base64.cpp
    src/core/terminal_ui.cpp
    src/core/UIManager.cpp
    src/core/UIManagerFactory.cpp
    src/core/clipboard.cpp
    src/core/qrcodegen.cpp
    src/config/GlobalConfig.cpp
    src/crypto/cipher_context_raii.cpp
    src/utils/filesystem_utils.cpp
    src/utils/error_utils.cpp
    src/utils/backup_utils.cpp
)

# Client-side vault: crypto, format, stores, sync (docs/PROTOCOL.md)
set(VAULT_SOURCES
    src/vault/Crypto.cpp
    src/vault/VaultFormat.cpp
    src/vault/LocalFileStore.cpp
    src/vault/Syncer.cpp
    src/vault/VaultService.cpp
    src/vault/EspStore.cpp
    src/vault/Pairing.cpp
    src/vault/PinUnlock.cpp
)

set(CLI_SOURCES
    src/cli/TerminalUIManager.cpp
)

set(GUI_SOURCES
    src/gui/GuiUIManager.cpp
    src/gui/Theme.cpp
    src/gui/Widgets.cpp
    src/gui/UpdateDialog.cpp
    src/updater/AppUpdater.cpp
)

# --- Filesystem library ---
if(UNIX AND NOT APPLE)
    set(FILESYSTEM_LIB stdc++fs)
else()
    set(FILESYSTEM_LIB "")
endif()

function(link_common target)
    # ARGN contains all arguments after 'target'
    set(EXTRA_INCLUDES ${ARGN})

    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
        ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto
        ${CMAKE_CURRENT_SOURCE_DIR}/src/config
        ${CMAKE_CURRENT_SOURCE_DIR}/src/utils
        ${CMAKE_CURRENT_SOURCE_DIR}/src/updater
        ${CMAKE_CURRENT_SOURCE_DIR}/src/vault
        ${JSON_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${FLTK_INCLUDE_DIR}
        ${EXTRA_INCLUDES}
    )

    # Link libraries
    if(FILESYSTEM_LIB)
        target_link_libraries(${target} PRIVATE ${FILESYSTEM_LIB})
    endif()
    target_link_libraries(${target} PRIVATE ${OPENSSL_LIBRARIES})
    if(JSON_LIB)
        # As a compile option, not an include dir: inside nix-shell the compiler already has this dir implicitly,
        # so CMake would drop it from the flags, and builds from any other shell couldn't find json.hpp.
        get_target_property(JSON_INC ${JSON_LIB} INTERFACE_INCLUDE_DIRECTORIES)
        target_compile_options(${target} PRIVATE -isystem ${JSON_INC})
    endif()

    # Link CURL on Unix systems
    if(NOT WIN32 AND CURL_FOUND)
        target_link_libraries(${target} PRIVATE ${CURL_LIBRARIES})
        target_include_directories(${target} PRIVATE ${CURL_INCLUDE_DIRS})
    endif()
endfunction()

# --- Main executable with unified UI ---

# Single unified application that can run both GUI and CLI modes
add_executable(password_manager
    ${CORE_SOURCES}
    ${VAULT_SOURCES}
    ${CLI_SOURCES}
    ${GUI_SOURCES}
    src/main.cpp
    src/tui_main.cpp
    src/gui_main.cpp
)

# Add compile definitions for both modes
target_compile_definitions(password_manager PRIVATE ENABLE_CLI ENABLE_GUI)

# Link all required libraries
target_link_libraries(password_manager PRIVATE ${FLTK_LIBRARIES})

# FLTK's Xft backend uses fontconfig without FcInit(); Theme.cpp calls it to silence the warning
if(UNIX AND NOT APPLE)
    find_package(Fontconfig REQUIRED)
    target_link_libraries(password_manager PRIVATE Fontconfig::Fontconfig)
    target_compile_definitions(password_manager PRIVATE HAVE_FONTCONFIG)
endif()

# Add Windows-specific libraries for updater
if(WIN32)
    target_link_libraries(password_manager PRIVATE wininet urlmon)
endif()

# Include directories for both GUI and CLI
link_common(password_manager ${CMAKE_CURRENT_SOURCE_DIR}/src/gui ${CMAKE_CURRENT_SOURCE_DIR}/src/cli)

# --- Create data directory (only once per build) ---
add_custom_target(create_data_dir ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/data
)

# --- Base64 Test executable ---
add_executable(base64_test tests/base64_test.cpp src/core/base64.cpp)
link_common(base64_test)

# --- Vault tests (protocol vectors + sync) ---
add_executable(vault_test tests/vault_test.cpp ${VAULT_SOURCES} src/core/base64.cpp src/crypto/cipher_context_raii.cpp)
target_compile_definitions(vault_test PRIVATE VECTORS_PATH="${CMAKE_CURRENT_SOURCE_DIR}/tests/protocol_vectors.json")
link_common(vault_test)

# --- Linting targets ---
find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT)
    add_custom_target(format
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/lint.sh --format --fix
        COMMENT "Running clang-format"
        VERBATIM
    )
endif()

find_program(CLANG_TIDY clang-tidy)
if(CLANG_TIDY)
    add_custom_target(tidy
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/lint.sh --tidy
        COMMENT "Running clang-tidy"
        VERBATIM
    )
endif()

add_custom_target(lint
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/lint.sh --all
    COMMENT "Running all linters"
    VERBATIM
)

# --- Install (optional; skip for local dev to speed up) ---
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    message(STATUS "Skipping install step for faster local builds")
else()
    install(TARGETS password_manager
        RUNTIME DESTINATION bin
    )
endif()
