#include "../core/ui.h"
#include "../core/api.h"
#include <iostream>

int main() {
    try {
        if (UI::login()) {
            int menu_choice;
            CredentialsManager manager(data_path);
            do {
                menu_choice = UI::display_menu();
                switch (menu_choice) {
                case 1:
                    manager.updatePassword();
                    break;
                case 2:
                    manager.addCredentials();
                    UI::pause_screen();
                    UI::clear_screen();
                    break;
                case 3:
                    manager.copyCredentials();
                    UI::pause_screen();
                    UI::clear_screen();
                    break;
                case 4:
                    manager.deleteCredentials();
                    break;
                case 5:
                    manager.showOptions();
                    UI::pause_screen();
                    UI::clear_screen();
                    break;
                case 0:
                    UI::display_message("Exiting the program...");
                    exit(0);
                default:
                    UI::display_message("Invalid choice. Please try again.");
                    break;
                }
            } while (menu_choice != 0);
            UI::pause_screen();
            UI::clear_screen();
        }
    } catch (const std::exception &e) {
        UI::display_message("Error: " + std::string(e.what()));
    }
    return 0;
}