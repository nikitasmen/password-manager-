#ifndef CLI_UI_H
#define CLI_UI_H

#include <string>
#include "../core/api.h" // Include CredentialsManager header

/**
 * @class TerminalAppController
 * @brief Controller for terminal application logic
 * 
 * This class encapsulates the main application logic for the terminal UI,
 * including login, password management, and credential handling.
 */
class TerminalAppController {
public:
    /**
     * @brief Handle user login
     * 
     * @return bool True if login is successful
     */
    static bool login();
    static void update_password();
    static void add_credentials();
    static void delete_credentials();
    static void show_credentials();
    static void copy_credentials();
};

#endif // CLI_UI_H