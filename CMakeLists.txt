cmake_minimum_required(VERSION 3.10)
project(password_manager)

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# JSON library - using manual inclusion instead of FetchContent
# Create a directory for the JSON library header
set(JSON_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/include)
file(MAKE_DIRECTORY ${JSON_INCLUDE_DIR}/nlohmann)

# Download the JSON single-header file
file(DOWNLOAD
    https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
    ${JSON_INCLUDE_DIR}/nlohmann/json.hpp
    SHOW_PROGRESS
)

# Add the include directory to the include path
include_directories(${JSON_INCLUDE_DIR})

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
    src/core/api.cpp
    src/core/EncryptionParamsBuilder.cpp
    src/core/base64.cpp
    src/core/encryption.cpp
    src/core/json_storage.cpp
    src/core/terminal_ui.cpp
    src/core/UIManager.cpp
    src/core/UIManagerFactory.cpp
    src/core/clipboard.cpp
    src/config/GlobalConfig.cpp
    src/config/MigrationHelper.cpp
    src/crypto/encryption_factory.cpp
    src/crypto/aes_encryption.cpp
    src/crypto/lfsr_encryption.cpp
    src/crypto/rsa_encryption.cpp
    src/crypto/cipher_context_raii.cpp
    src/crypto/pkey_ctx_raii.cpp
    src/utils/filesystem_utils.cpp
    src/utils/error_utils.cpp
    src/utils/backup_utils.cpp
)

set(CLI_SOURCES
    src/cli/TerminalUIManager.cpp
)

set(GUI_SOURCES
    src/gui/GuiUIManager.cpp
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

# --- Install (optional; skip for local dev to speed up) ---
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    message(STATUS "Skipping install step for faster local builds")
else()
    install(TARGETS password_manager
        RUNTIME DESTINATION bin
    )
endif()
