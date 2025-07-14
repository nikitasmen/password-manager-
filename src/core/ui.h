#ifndef UI_H
#define UI_H

#include <string>
#include <vector>

/**
 * @class UI
 * @brief User Interface handling class
 * 
 * Provides methods for handling console user interface interactions,
 * including menus, message display, and secure password input
 */
class UI {
public:
    /**
     * @brief Display the main menu and get user choice
     * 
     * @return int The menu option selected by the user
     */
    static int display_menu();
    
    /**
     * @brief Display a message to the user
     * 
     * @param message The message to display
     * @param isError If true, message will be displayed as an error
     */
    static void display_message(const std::string& message, bool isError = false);
    
    /**
     * @brief Get password input with masked characters
     * 
     * @param prompt The prompt to display before input
     * @return std::string The password entered by the user
     */
    static std::string get_password_input(const std::string& prompt);
    
    /**
     * @brief Get text input from the user
     * 
     * @param prompt The prompt to display before input
     * @return std::string The text entered by the user
     */
    static std::string get_text_input(const std::string& prompt);
    
    /**
     * @brief Clear the console screen
     */
    static void clear_screen();
    
    /**
     * @brief Pause execution until user presses Enter
     */
    static void pause_screen();
    
    /**
     * @brief Display a list of items with a header
     * 
     * @param items List of items to display
     * @param header Header text for the list
     */
    static void display_list(const std::vector<std::string>& items, const std::string& header);
    
    /**
     * @brief Show a confirmation prompt and get yes/no response
     * 
     * @param message The confirmation message
     * @return bool True if user confirms, false otherwise
     */
    static bool confirm(const std::string& message);
    
    /**
     * @brief Handle login procedure
     * 
     * @param maxAttempts Maximum number of login attempts
     * @return bool True if login successful, false otherwise
     */
    static bool login(int maxAttempts = 3);
};

#endif // UI_H
