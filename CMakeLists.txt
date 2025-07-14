cmake_minimum_required(VERSION 3.10)
project(password_manager)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find FLTK package
find_package(FLTK REQUIRED)
include_directories(${FLTK_INCLUDE_DIR})

# Source files
set(CORE_SOURCES
    src/core/api.cpp
    src/core/encryption.cpp
    src/core/fileSys.cpp
    src/core/ui.cpp
    GlobalConfig.cpp
)

set(CLI_SOURCES
    src/cli/cli_api.cpp
    src/cli/cli_ui.cpp
    src/mainApi.cpp
)

set(UI_SOURCES
    src/mainUi.cpp
)

set(GUI_SOURCES
    src/gui/gui.cpp
    src/mainGui.cpp
)

set(DATA_SOURCES
    src/data/data.cpp
)

# Create CLI executable
add_executable(cli_api ${CORE_SOURCES} ${CLI_SOURCES} ${DATA_SOURCES})
target_include_directories(cli_api PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Create interactive UI executable
add_executable(password_manager ${CORE_SOURCES} ${UI_SOURCES} ${DATA_SOURCES} src/cli/cli_ui.cpp)
target_include_directories(password_manager PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Create GUI executable
add_executable(password_manager_gui ${CORE_SOURCES} ${GUI_SOURCES} ${DATA_SOURCES})
target_include_directories(password_manager_gui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(password_manager_gui ${FLTK_LIBRARIES})

# Create the data directory if it doesn't exist
add_custom_command(
    TARGET password_manager POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/data
)

add_custom_command(
    TARGET password_manager_gui POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/data
)

# Install executables
install(TARGETS cli_api password_manager password_manager_gui
    RUNTIME DESTINATION bin
)
