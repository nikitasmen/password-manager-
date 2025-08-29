#include "backup_utils.h"

#include <chrono>
#include <iomanip>
#include <sstream>

#include "error_utils.h"
#include "filesystem_utils.h"

namespace BackupUtils {

bool createBackup(const std::string& originalPath) {
    try {
        if (!FilesystemUtils::isRegularFile(originalPath)) {
            return true;  // Nothing to backup
        }

        // Create timestamp for backup name
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y%m%d_%H%M%S");

        // Create backup name with timestamp
        std::string baseBackupName = originalPath + ".backup." + ss.str();
        std::string backupName = baseBackupName;

        // Handle duplicate backup names by adding an index
        int index = 1;
        while (fs::exists(backupName)) {
            backupName = baseBackupName + "_" + std::to_string(index);
            index++;
        }

        // Copy the file
        std::error_code ec;
        fs::copy_file(originalPath, backupName, ec);
        if (ec) {
            ErrorUtils::logError("BackupUtils::createBackup",
                                 "Failed to copy " + originalPath + " to " + backupName + ": " + ec.message());
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        ErrorUtils::logException("BackupUtils::createBackup", e);
        return false;
    }
}

bool createSimpleBackup(const std::string& originalPath, const std::string& backupPath) {
    try {
        if (!FilesystemUtils::isRegularFile(originalPath)) {
            return true;  // Nothing to backup
        }

        std::error_code ec;
        fs::copy_file(originalPath, backupPath, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            ErrorUtils::logError("BackupUtils::createSimpleBackup",
                                 "Failed to copy " + originalPath + " to " + backupPath + ": " + ec.message());
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        ErrorUtils::logException("BackupUtils::createSimpleBackup", e);
        return false;
    }
}

bool removeBackup(const std::string& backupPath) {
    return FilesystemUtils::safeRemove(backupPath);
}

bool restoreFromBackup(const std::string& backupPath, const std::string& originalPath) {
    try {
        if (!FilesystemUtils::isRegularFile(backupPath)) {
            ErrorUtils::logError("BackupUtils::restoreFromBackup", "Backup file does not exist: " + backupPath);
            return false;
        }

        std::error_code ec;
        fs::copy_file(backupPath, originalPath, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            ErrorUtils::logError("BackupUtils::restoreFromBackup",
                                 "Failed to restore " + backupPath + " to " + originalPath + ": " + ec.message());
            return false;
        }

        // Remove backup after successful restore
        removeBackup(backupPath);
        return true;
    } catch (const std::exception& e) {
        ErrorUtils::logException("BackupUtils::restoreFromBackup", e);
        return false;
    }
}

int cleanupOrphanedBackups(const std::string& directory, const std::string& pattern) {
    int cleaned = 0;
    try {
        if (!FilesystemUtils::isDirectory(directory)) {
            return 0;
        }

        for (const auto& entry : fs::directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                // Simple pattern matching for .backup files
                if (filename.find(".backup") != std::string::npos) {
                    if (FilesystemUtils::safeRemove(entry.path().string())) {
                        cleaned++;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        ErrorUtils::logException("BackupUtils::cleanupOrphanedBackups", e);
    }

    return cleaned;
}

}  // namespace BackupUtils
