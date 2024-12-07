#include "./MainFunctionality.h"
#include "./UI.h"
#include <vector>

std::vector<int> taps = {0, 2};          // Taps for a 3-bit LFSR (x^3 + x^1 + 1)
std::vector<int> init_state = {1, 0, 1}; // Initial state [1, 0, 1]


int main() {
    try {
        if (MainFunctionality::login()) {
            int menu_choice;
            do {
                menu_choice = UI::display_menu();
                switch (menu_choice) {
                case 1:
                    MainFunctionality::update_password();
                    break;
                case 2:
                    MainFunctionality::add_credentials();
                    UI::pause_screen(); 
                    UI::clear_screen();
                    break;
                case 3:
                    MainFunctionality::copy_credentials();
                    UI::pause_screen(); 
                    UI::clear_screen();
                    break;
                case 4:
                    MainFunctionality::delete_credentials();
                    break;
                case 5:
                    MainFunctionality::show_credentials();
                    UI::pause_screen(); 
                    UI::clear_screen();
                    break;
                }
            } while (menu_choice != 0);
        }
    } catch (const std::exception& e) {
        UI::display_message("Error: " + std::string(e.what()));
    }
    return 0;
}
