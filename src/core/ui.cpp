#include "UI.h"
#include <iostream>
#include <limits>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

int UI::display_menu() {
    int choice;
    std::cout << "\n=========================================\n";
    std::cout << "          PASSWORD MANAGER MENU          \n";
    std::cout << "=========================================\n";
    std::cout << "1) Change Login Password\n";
    std::cout << "2) Add New Platform Credentials\n";
    std::cout << "3) Copy Credentials to Clipboard\n";
    std::cout << "4) Delete Platform Credentials\n";
    std::cout << "5) Show All Stored Platforms\n";
    std::cout << "0) Exit\n";
    std::cout << "-----------------------------------------\n";
    std::cout << "Enter your choice: ";
    
    std::cin >> choice;
    if (std::cin.fail() || choice < 0 || choice > 5) {
        std::cin.clear(); // Clear the error flag
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
        std::cout << "\n[ERROR] Invalid choice. Please try again.\n";
        return display_menu(); // Recursively call to prompt again
    }

    return choice;
}

void UI::display_message(const std::string& message) {
    std::cout << message << std::endl;
}

std::string UI::get_password_input(const std::string& prompt) {
    std::string input;
    struct termios oldt, newt;

    std::cout << prompt;

    // Get current terminal settings
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    // Disable echo
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // Read input
    std::cin >> input;

    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    std::cout << std::endl; // For neat output
    return input;
}

void UI::clear_screen() {
    #ifdef _WIN32
    system("cls");
    #else
    system("clear");
    #endif
}


void UI::pause_screen() {
    std::cout << "Press Enter to continue...";
    std::cin.get();
}

bool UI::login() { 
    std::string password;
    std::cout << "Enter login password: ";
    password = get_password_input("");
    return password == "password";
}