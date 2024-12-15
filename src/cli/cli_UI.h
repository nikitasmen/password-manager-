#ifndef CLI_UI_H
#define CLI_UI_H

#include <string>

class MainFunctionality {
public:
    static bool login();
    static void update_password();
    static void add_credentials();
    static void delete_credentials();
    static void show_credentials();
    static void copy_credentials();
};

#endif // CLI_UI_H