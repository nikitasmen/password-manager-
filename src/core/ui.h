#ifndef UI_H
#define UI_H

#include <string>

class UI {
public:
    static int display_menu();
    static void display_message(const std::string& message);
    static std::string get_password_input(const std::string& prompt);
    static void clear_screen();
    static void pause_screen(); 
    static bool login();
};

#endif // UI_H
