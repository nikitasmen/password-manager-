#include "./ui.h"
#include "../core/api.h"
#include "../../GlobalConfig.h"
#include <iostream>
#include <limits>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

int UI::display_menu() {
    int choice;
    std::cout << "\n+---------------------------------------+\n";
    std::cout << "|          PASSWORD MANAGER MENU          |\n";
    std::cout << "+---------------------------------------+\n";
    std::cout << "| 1) Change Master Password               |\n";
    std::cout << "| 2) Add New Platform Credentials         |\n";
    std::cout << "| 3) Retrieve Platform Credentials        |\n";
    std::cout << "| 4) Delete Platform Credentials          |\n";
    std::cout << "| 5) Show All Stored Platforms            |\n";
    std::cout << "| 0) Exit                                 |\n";
    std::cout << "+---------------------------------------+\n";
    std::cout << "Enter your choice: ";
    
    if (!(std::cin >> choice)) {
        std::cin.clear(); // Clear the error flag
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
        display_message("Invalid input. Please enter a number.", true);
        return display_menu(); // Recursively call to prompt again
    }
    
    // Consume the newline
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    if (choice < 0 || choice > 5) {
        display_message("Invalid menu option. Please try again.", true);
        return display_menu(); // Recursively call to prompt again
    }

    return choice;
}

void UI::display_message(const std::string& message, bool isError) {
    if (isError) {
        std::cerr << "\033[1;31m[ERROR] " << message << "\033[0m" << std::endl;
    } else {
        std::cout << message << std::endl;
    }
}

std::string UI::get_password_input(const std::string& prompt) {
    std::string input;
    
    if (!prompt.empty()) {
        std::cout << prompt;
    }

#ifdef _WIN32
    // Windows implementation
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    
    std::getline(std::cin, input);
    
    SetConsoleMode(hStdin, mode);
#else
    // Unix/Linux/MacOS implementation
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::getline(std::cin, input);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    std::cout << std::endl; // For neat output
    return input;
}

std::string UI::get_text_input(const std::string& prompt) {
    std::string input;
    
    if (!prompt.empty()) {
        std::cout << prompt;
    }
    
    std::getline(std::cin, input);
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
    std::cout << "\nPress Enter to continue...";
    std::cin.get();
}

void UI::display_list(const std::vector<std::string>& items, const std::string& header) {
    if (items.empty()) {
        display_message("No items to display.", false);
        return;
    }
    
    size_t maxWidth = header.length();
    
    // Find the maximum width needed
    for (const auto& item : items) {
        if (item.length() > maxWidth) {
            maxWidth = item.length();
        }
    }
    
    // Add padding
    maxWidth += 4;
    
    // Print the header with border
    std::cout << "\n+" << std::string(maxWidth + 2, '-') << "+" << std::endl;
    std::cout << "| " << header << std::string(maxWidth - header.length(), ' ') << " |" << std::endl;
    std::cout << "+" << std::string(maxWidth + 2, '-') << "+" << std::endl;
    
    // Print each item
    for (size_t i = 0; i < items.size(); i++) {
        std::cout << "| " << (i+1) << ". " << items[i] 
                  << std::string(maxWidth - items[i].length() - 3 - std::to_string(i+1).length(), ' ') 
                  << " |" << std::endl;
    }
    
    // Print the bottom border
    std::cout << "+" << std::string(maxWidth + 2, '-') << "+" << std::endl;
}

bool UI::confirm(const std::string& message) {
    std::string input;
    std::cout << message << " (y/n): ";
    std::cin >> input;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear the buffer
    
    return (input == "y" || input == "Y" || input == "yes" || input == "Yes");
}

bool UI::login(int maxAttempts) {
    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
        clear_screen();
        std::cout << "+---------------------------------------+\n";
        std::cout << "|          PASSWORD MANAGER LOGIN         |\n";
        std::cout << "+---------------------------------------+\n";
        
        if (attempt > 1) {
            display_message("Login failed. Attempt " + std::to_string(attempt) + 
                          " of " + std::to_string(maxAttempts), true);
        }
        
        std::string password = get_password_input("Enter master password: ");
        
        // Validate the password using CredentialsManager
        CredentialsManager manager(data_path);
        if (manager.login(password)) {
            display_message("Login successful!");
            return true;
        }
    }
    
    display_message("Maximum login attempts exceeded. Exiting...", true);
    return false;
}