#include "../core/api.h"
#include "../core/ui.h"
#include <iostream>
// extern std::string data_path;   

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <userPassword> <option> [values...]\n";
        return 1;
    }

    std::string userPassword = argv[1];
    std::string option = argv[2];

    CredentialsManager manager();

    if (!manager.login(userPassword)) {
        std::cerr << "Invalid password.\n";
        return 1;
    }

    if (option == "-h") {
        std::cout << "Options:\n";
        std::cout << "-h (help) // Show manual\n";
        std::cout << "-a (add) <platform> <user> <pass> // Add password\n";
        std::cout << "-s (show) // Return all records\n";
        std::cout << "-c (copy) <platform> // Return and copy record specified by platform's name\n";
    } else if (option == "-a" && argc == 6) {
        std::string platform = argv[3];
        std::string user = argv[4];
        std::string pass = argv[5];
        if (manager.addCredentials(platform, user, pass)) {
            std::cout << "Credentials added successfully.\n";
        } else {
            std::cerr << "Failed to add credentials.\n";
        }
    } else if (option == "-s") {
        manager.showOptions(data_path);
    } else if (option == "-c" && argc == 4) {
        std::string platform = argv[3];
        auto credentials = manager.getCredentials(platform);
        if (!credentials.empty()) {
            std::cout << "Credentials for " << platform << ":\n";
            for (const auto &cred : credentials) {
                std::cout << cred << "\n";
            }
        } else {
            std::cerr << "No credentials found for " << platform << ".\n";
        }
    } else {
        std::cerr << "Invalid option or missing arguments.\n";
    }

    return 0;
}