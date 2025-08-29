#ifndef UI_MANAGER_FACTORY_H
#define UI_MANAGER_FACTORY_H

#include <memory>
#include <string>

#include "../core/UIManager.h"

/**
 * @enum UIType
 * @brief Enum for different UI types
 */
enum class UIType {
    TERMINAL,  // Terminal/Console UI
    GUI        // Graphical User Interface
};

/**
 * @class UIManagerFactory
 * @brief Factory class for creating UI managers
 *
 * This class provides a factory method to create the appropriate
 * UI manager implementation based on the UI type.
 */
class UIManagerFactory {
   public:
    /**
     * @brief Create a UI manager
     * @param type UI type to create
     * @param dataPath Path to the data storage directory
     * @return Unique pointer to UIManager implementation
     */
    static std::unique_ptr<UIManager> createUIManager(UIType type, const std::string& dataPath);
};

#endif  // UI_MANAGER_FACTORY_H
