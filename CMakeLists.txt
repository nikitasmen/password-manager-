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
include_directories(${FLTK_INCLUDE_DIR})

# --- Find OpenSSL for AES encryption ---
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# --- Source files ---
set(CORE_SOURCES
    src/core/api.cpp
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
    src/crypto/cipher_context_raii.cpp
)

set(CLI_SOURCES
    src/cli/TerminalUIManager.cpp
)

set(GUI_SOURCES
    src/gui/GuiUIManager.cpp
)

# --- Filesystem library ---
if(UNIX AND NOT APPLE)
    set(FILESYSTEM_LIB stdc++fs)
else()
    set(FILESYSTEM_LIB "")
endif()

function(link_common target)
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${JSON_INCLUDE_DIR})
    if(FILESYSTEM_LIB)
        target_link_libraries(${target} PRIVATE ${FILESYSTEM_LIB})
    endif()
    # Link OpenSSL
    target_link_libraries(${target} PRIVATE ${OPENSSL_LIBRARIES})
endfunction()

# --- Main executables with UI abstraction ---

# CLI application
add_executable(password_manager_cli ${CORE_SOURCES} ${CLI_SOURCES} src/tui_main.cpp)
link_common(password_manager_cli)
target_compile_definitions(password_manager_cli PRIVATE ENABLE_CLI)

# GUI application
add_executable(password_manager_gui ${CORE_SOURCES} ${GUI_SOURCES} src/gui_main.cpp)
target_compile_definitions(password_manager_gui PRIVATE ENABLE_GUI)
target_link_libraries(password_manager_gui PRIVATE ${FLTK_LIBRARIES})
link_common(password_manager_gui)

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
    install(TARGETS password_manager_cli password_manager_gui
        RUNTIME DESTINATION bin
    )
endif()
