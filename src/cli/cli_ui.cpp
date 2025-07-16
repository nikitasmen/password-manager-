#include "../core/terminal_ui.h"
#include "../core/api.h"
#include "./cli_ui.h"
#include "../config/GlobalConfig.h"
#include <iostream>

bool TerminalAppController::login() {
    return TerminalUI::login();
}

void TerminalAppController::update_password() {
    std::string newPassword = TerminalUI::get_password_input("Enter new password: ");
    
    // Create a manager instance using the proper constructor
    CredentialsManager manager(data_path);
    
    if (manager.updatePassword(newPassword)) {
        TerminalUI::display_message("Password updated successfully.");
    } else {
        TerminalUI::display_message("Failed to update password.");
    }
}

void TerminalAppController::add_credentials() {
    std::string platform = TerminalUI::get_password_input("Enter platform name: ");
    std::string username = TerminalUI::get_password_input("Enter username: ");
    std::string password = TerminalUI::get_password_input("Enter password: ");
    
    CredentialsManager manager(data_path);
    
    if (manager.addCredentials(platform, username, password)) {
        TerminalUI::display_message("Credentials added successfully.");
    } else {
        TerminalUI::display_message("Failed to add credentials.");
    }
}

void TerminalAppController::delete_credentials() {
    std::string platform = TerminalUI::get_password_input("Enter platform name to delete: ");
    
    CredentialsManager manager(data_path);
    
    if (manager.deleteCredentials(platform)) {
        TerminalUI::display_message("Credentials deleted successfully.");
    } else {
        TerminalUI::display_message("Failed to delete credentials.");
    }
}

void TerminalAppController::show_credentials() {
    CredentialsManager manager(data_path);
    manager.showOptions();
}

void TerminalAppController::copy_credentials() {
    std::string platform = TerminalUI::get_password_input("Enter platform name to copy: ");
    
    CredentialsManager manager(data_path);
    
    auto credentials = manager.getCredentials(platform);
    if (!credentials.empty()) {
        TerminalUI::display_message("Credentials copied to clipboard.");
        // Add logic to copy to clipboard if needed
    } else {
        TerminalUI::display_message("No credentials found for the specified platform.");
    }
}