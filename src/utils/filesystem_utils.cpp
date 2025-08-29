#include "filesystem_utils.h"

#include <iostream>

namespace FilesystemUtils {

bool isRegularFile(const std::string& path) {
    try {
        return fs::exists(path) && fs::is_regular_file(path);
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error checking file: " << path << " - " << e.what() << std::endl;
        return false;
    }
}

bool isDirectory(const std::string& path) {
    try {
        return fs::exists(path) && fs::is_directory(path);
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error checking directory: " << path << " - " << e.what() << std::endl;
        return false;
    }
}

bool safeRemove(const std::string& path) {
    try {
        std::error_code ec;
        bool result = fs::remove(path, ec);
        if (ec) {
            std::cerr << "Error removing file: " << path << " - " << ec.message() << std::endl;
            return false;
        }
        return true;  // Success even if file didn't exist
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error removing file: " << path << " - " << e.what() << std::endl;
        return false;
    }
}

bool createDirectories(const std::string& path) {
    try {
        std::error_code ec;
        bool result = fs::create_directories(path, ec);
        if (ec) {
            std::cerr << "Error creating directories: " << path << " - " << ec.message() << std::endl;
            return false;
        }
        return true;  // Success even if directory already existed
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error creating directories: " << path << " - " << e.what() << std::endl;
        return false;
    }
}

}  // namespace FilesystemUtils
