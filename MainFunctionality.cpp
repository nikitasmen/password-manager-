#include "MainFunctionality.h"
#include "GlobalConfig.h"  
#include "Encryption.h"
#include "UI.h"
#include <fstream>
#include <iostream>
#include <filesystem>

extern std::vector<int> taps;
extern std::vector<int> init_state;

bool MainFunctionality::login() {
    Encryption log(taps, init_state);
    std::string password, correct, value;
    
    std::string login_file = data_path + "/" + "enter";
    
    if (std::filesystem::exists(login_file)) {
        std::ifstream fin("enter", std::ios::binary);
        getline(fin, value); // Read encrypted value
        fin.close();

        correct = log.decrypt(value);

        int attempts = 0;
        while (attempts < 3) {
            password = UI::get_password_input("Enter your password: ");
            if (password == correct) {
                return true;
            }
            UI::display_message("Wrong password. Try again.");
            attempts++;
        }
        return false;
    } else {
        std::cout << "No existing password found. Create a new password: ";
         password = UI::get_password_input("Enter your password: ");
        if (!password.empty()) {
            std::string encrypted = log.encrypt(password);
            try{
                std::ofstream fout(login_file, std::ios::binary);
                fout << encrypted;
                fout.close();
            } catch (std::exception& e) {
                // std::cout << "Error: " << e.what() << std::endl;
                return false;
            }
            return true;
        }
    }
    return false;
}


void MainFunctionality::update_password() {
    Encryption log(taps, init_state);
    std::string new_password;

    std::cout << "Enter the new login password (or 0 to cancel): ";
    std::cin >> new_password;
    if (new_password != "0") {
        std::ofstream fout("enter", std::ofstream::out | std::ofstream::trunc);
        fout << log.encrypt(new_password);
        fout.close();
        std::cout << "Password successfully updated.\n";
    } else {
        std::cout << "Password change canceled.\n";
    }
}


void MainFunctionality::add_credentials() {
    Encryption log(taps, init_state);
    std::string platform_name, username, password;

    std::cout << "Enter platform's name (or 0 to cancel): ";
    std::cin >> platform_name;
    if (platform_name == "0") {
        std::cout << "Add operation canceled.\n";
        return;
    }

    std::string filename = data_path + "/" + platform_name; 
    if (std::filesystem::exists(filename)) {
        std::cout << "File already exists. Unable to add new platform.\n";
        return;
    }

    std::cout << "Enter platform's username: ";
    std::cin >> username;
    password = UI::get_password_input("Enter platform's password: "); 

    username = log.encrypt(username);
    password = log.encrypt(password);

    std::ofstream fout(filename, std::ios::binary);
    fout << username << "\n" << password;
    fout.close();

#ifdef _WIN32
    DWORD attributes = GetFileAttributes(filename.c_str());
    SetFileAttributes(filename.c_str(), attributes | FILE_ATTRIBUTE_HIDDEN);
#endif

    std::cout << "Platform data successfully added and encrypted.\n";

}




void MainFunctionality::copy_credentials() {
    Encryption dec(taps, init_state);
    std::ifstream fin;
    std::string platform_name, encrypted_value, decrypted_value;

    std::cout << "Enter platform's name you want to copy (or 0 to cancel): ";
    std::cin >> platform_name;

    if (platform_name == "0") {
        std::cout << "Copy operation canceled.\n";
        return;
    }

    std::string filename = data_path + "/" + platform_name;

    // Check if file exists
    if (!std::filesystem::exists(filename)) {
        std::cout << "Record does not exist.\n";
        return;
    }

    // Read the file
    fin.open(filename, std::ios::binary);
    if (!fin) {
        std::cout << "Failed to open the file.\n";
        return;
    }

    std::cout << "Decrypted data:\n";
    while (getline(fin, encrypted_value)) {
        decrypted_value = dec.decrypt(encrypted_value);
        std::cout << decrypted_value << "\n";

#ifdef _WIN32
        // Copy decrypted value to clipboard (Windows-specific)
        int length = decrypted_value.length() + 1; // Include null terminator
        HGLOBAL global = GlobalAlloc(GMEM_MOVEABLE, length);
        if (global) {
            void* locked_memory = GlobalLock(global);
            memcpy(locked_memory, decrypted_value.c_str(), length);
            GlobalUnlock(global);

            if (OpenClipboard(nullptr)) {
                EmptyClipboard();
                SetClipboardData(CF_TEXT, global);
                CloseClipboard();
                cout << "Password copied to clipboard.\n";
            } else {
                cout << "Failed to open clipboard.\n";
                GlobalFree(global);
            }
        } else {
            cout << "Failed to allocate memory for clipboard operation.\n";
        }
#else
    #ifdef __linux__
        // Copy decrypted value to clipboard using xclip or xsel
        FILE* pipe = popen("xclip -selection clipboard", "w");
        if (pipe) {
            fwrite(decrypted_value.c_str(), 1, decrypted_value.size(), pipe);
            pclose(pipe);
            std::cout << "Password copied to clipboard.\n";
        } else {
            std::cout << "Failed to copy to clipboard. Ensure xclip is installed.\n";
        }
    #endif
#endif
    }

    fin.close();
}

void MainFunctionality::delete_credentials() {
    std::string platform_name;

    std::cout << "Enter platform's name to delete (or 0 to cancel): ";
    std::cin >> platform_name;
    if (platform_name == "0") {
        std::cout << "Delete operation canceled.\n";
        return;
    }

    std::string filename = data_path + "/" + platform_name;
    if (std::filesystem::exists(filename)) {
        std::filesystem::remove(filename);
        std::cout << "Record successfully deleted.\n";
    } else {
        std::cout << "Record does not exist.\n";
    }
}



void MainFunctionality::show_credentials() {
    std::string path;

    std::cout << "Enter the directory path to scan for records (press Enter to use default path): ";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear the input buffer
    std::getline(std::cin, path);

    // Use default path if input is empty
    if (path.empty()) {
        path = data_path;
    }

    // Check if directory exists
    if (!std::filesystem::exists(path) || !std::filesystem::is_directory(path)) {
        std::cout << "Invalid directory path. Please try again.\n";
        return;
    }

    std::cout << "Listing files in the directory:\n";
    for (const auto& file : std::filesystem::directory_iterator(path)) {
        if (file.is_regular_file()) { // Only display files
            std::cout << file.path().filename().string() << std::endl;
        }
    }
}
