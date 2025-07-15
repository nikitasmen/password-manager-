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

# --- Source files ---
set(CORE_SOURCES
    src/core/api.cpp
    src/core/base64.cpp
    src/core/encryption.cpp
    src/core/file_system.cpp
    src/core/json_storage.cpp
    src/core/ui.cpp
    src/config/GlobalConfig.cpp
)

set(CLI_SOURCES
    src/cli/cli_api.cpp
    src/cli/cli_ui.cpp
    src/cli_main.cpp
)

set(UI_SOURCES src/terminal_main.cpp)

set(GUI_SOURCES
    src/gui/gui.cpp
    src/gui_main.cpp
)

set(DATA_SOURCES src/data/data.cpp)

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
endfunction()

# --- CLI executable ---
add_executable(cli_api ${CORE_SOURCES} ${CLI_SOURCES} ${DATA_SOURCES})
link_common(cli_api)

# --- Interactive UI executable ---
add_executable(password_manager ${CORE_SOURCES} ${UI_SOURCES} ${DATA_SOURCES} src/cli/cli_ui.cpp)
link_common(password_manager)

# --- GUI executable ---
add_executable(password_manager_gui ${CORE_SOURCES} ${GUI_SOURCES} ${DATA_SOURCES})
target_link_libraries(password_manager_gui ${FLTK_LIBRARIES})
link_common(password_manager_gui)

# --- Create data directory (only once per build) ---
add_custom_target(create_data_dir ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/data
)

# --- Install (optional; skip for local dev to speed up) ---
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    message(STATUS "Skipping install step for faster local builds")
else()
    install(TARGETS cli_api password_manager password_manager_gui
        RUNTIME DESTINATION bin
    )
endif()
