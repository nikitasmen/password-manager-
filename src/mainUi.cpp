#include "./cli/cli_ui.h"
#include "./core/ui.h"
#include <vector>

int main()
{
    try
    {
        if (MainFunctionality::login())
        {
            int menu_choice;
            do
            {
                menu_choice = UI::display_menu();
                switch (menu_choice)
                {
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
    }
    catch (const std::exception &e)
    {
        UI::display_message("Error: " + std::string(e.what()));
    }
    return 0;
}
