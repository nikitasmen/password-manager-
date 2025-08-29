#ifndef FILESYSTEM_UTILS_H
#define FILESYSTEM_UTILS_H

// Consistent filesystem include handling across the project
#if __has_include(<filesystem>)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

// Common filesystem utility functions
namespace FilesystemUtils {
/**
 * @brief Safely check if a path exists and is a regular file
 * @param path The path to check
 * @return true if path exists and is a regular file
 */
bool isRegularFile(const std::string& path);

/**
 * @brief Safely check if a path exists and is a directory
 * @param path The path to check
 * @return true if path exists and is a directory
 */
bool isDirectory(const std::string& path);

/**
 * @brief Safely remove a file with error handling
 * @param path The file path to remove
 * @return true if successful or file doesn't exist
 */
bool safeRemove(const std::string& path);

/**
 * @brief Create directories recursively with error handling
 * @param path The directory path to create
 * @return true if successful or already exists
 */
bool createDirectories(const std::string& path);
}  // namespace FilesystemUtils

#endif  // FILESYSTEM_UTILS_H
