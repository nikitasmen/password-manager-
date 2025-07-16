#include "./cli/cli_UI.h"
#include "./core/terminal_ui.h"
#include <vector>

int main()
{
    try
    {
        if (TerminalAppController::login())
        {
            int menu_choice;
            do
            {
                menu_choice = TerminalUI::display_menu();
                switch (menu_choice)
                {
                case 1:
                    TerminalAppController::update_password();
                    TerminalUI::pause_screen();
                    TerminalUI::clear_screen();
                    break;
                case 2:
                    TerminalAppController::add_credentials();
                    TerminalUI::pause_screen();
                    TerminalUI::clear_screen();
                    break;
                case 3:
                    TerminalAppController::copy_credentials();
                    TerminalUI::pause_screen();
                    TerminalUI::clear_screen();
                    break;
                case 4:
                    TerminalAppController::delete_credentials();
                    break;
                case 5:
                    TerminalAppController::show_credentials();
                    TerminalUI::pause_screen();
                    TerminalUI::clear_screen();
                    break;                case 0:
                    TerminalUI::display_message("Exiting the program...");
                    exit(0);
                default:
                    TerminalUI::display_message("Invalid choice. Please try again.");   
                    break;
                }
            } while (menu_choice != 0);
                    TerminalUI::pause_screen();
                    TerminalUI::clear_screen();
        }
    }
    catch (const std::exception &e)
    {
        TerminalUI::display_message("Error: " + std::string(e.what()));
    }
    return 0;
}
