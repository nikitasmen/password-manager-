#include "../core/ui.h"
#include "../core/api.h"
#include "./cli_UI.h"
#include "../../GlobalConfig.h"
#include <iostream>

bool MainFunctionality::login() {
    return UI::login();
}

void MainFunctionality::update_password() {
    std::string newPassword = UI::get_password_input("Enter new password: ");
    CredentialsManager manager;
    if (manager.updatePassword(newPassword)) {
        UI::display_message("Password updated successfully.");
    } else {
        UI::display_message("Failed to update password.");
    }
}

void MainFunctionality::add_credentials() {
    std::string platform = UI::get_password_input("Enter platform name: ");
    std::string username = UI::get_password_input("Enter username: ");
    std::string password = UI::get_password_input("Enter password: ");
    CredentialsManager manager;
    if (manager.addCredentials(platform, username, password)) {
        UI::display_message("Credentials added successfully.");
    } else {
        UI::display_message("Failed to add credentials.");
    }
}

void MainFunctionality::delete_credentials() {
    std::string platform = UI::get_password_input("Enter platform name to delete: ");
    CredentialsManager manager;
    if (manager.deleteCredentials(platform)) {
        UI::display_message("Credentials deleted successfully.");
    } else {
        UI::display_message("Failed to delete credentials.");
    }
}

void MainFunctionality::show_credentials() {
    CredentialsManager manager;
    manager.showOptions();
}

void MainFunctionality::copy_credentials() {
    std::string platform = UI::get_password_input("Enter platform name to copy: ");
    CredentialsManager manager;
    auto credentials = manager.getCredentials(platform);
    if (!credentials.empty()) {
        UI::display_message("Credentials copied to clipboard.");
        // Add logic to copy to clipboard if needed
    } else {
        UI::display_message("No credentials found for the specified platform.");
    }
}