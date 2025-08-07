#ifndef BACKUP_UTILS_H
#define BACKUP_UTILS_H

#include <string>

/**
 * @brief Common backup file handling utilities
 */
namespace BackupUtils {
    /**
     * @brief Create a backup of a file with timestamp
     * @param originalPath Path to the file to backup
     * @return true if backup was successful
     */
    bool createBackup(const std::string& originalPath);
    
    /**
     * @brief Create a simple backup without timestamp (.backup suffix)
     * @param originalPath Path to the file to backup
     * @param backupPath Path where backup should be created
     * @return true if backup was successful
     */
    bool createSimpleBackup(const std::string& originalPath, const std::string& backupPath);
    
    /**
     * @brief Remove a backup file
     * @param backupPath Path to the backup file
     * @return true if removal was successful or file didn't exist
     */
    bool removeBackup(const std::string& backupPath);
    
    /**
     * @brief Restore from backup and remove the backup file
     * @param backupPath Path to the backup file
     * @param originalPath Path where to restore the backup
     * @return true if restore was successful
     */
    bool restoreFromBackup(const std::string& backupPath, const std::string& originalPath);
    
    /**
     * @brief Clean up orphaned backup files in a directory
     * @param directory Directory to clean
     * @param pattern Pattern to match (e.g., "*.backup")
     * @return Number of files cleaned up
     */
    int cleanupOrphanedBackups(const std::string& directory, const std::string& pattern = "*.backup");
}

#endif // BACKUP_UTILS_H
