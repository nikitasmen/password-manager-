#include <vector>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <limits>





#ifdef _WIN32
    #include <conio.h>
    #include <Windows.h>
#else
    #include <termios.h>
    #include <unistd.h>
#endif

using std::cin;
using std::cout;
using std::endl;

std::vector<int> taps = {0, 2};         // Taps for a 3-bit LFSR (x^3 + x^1 + 1)
std::vector<int> init_state = {1, 0, 1}; // Initial state [1, 0, 1]

// Function declarations
bool login();
int menu();
void change();
void add();
void del();
void show();
void copy();

std::string get_password(const std::string& prompt); 

class Login {
private:
    std::vector<int> taps;
    std::vector<int> state;

public:
    Login(const std::vector<int>& taps, const std::vector<int>& init_state) {
        if (init_state.size() < taps.back() + 1) {
            throw std::invalid_argument("Initial state size is too small for the specified taps.");
        }
        this->taps = taps;
        this->state = init_state;
    }

    std::string encrypt(const std::string& plaintext) {
        std::string encrypted;
        for (char c : plaintext) {
            int keystream_bit = state[0]; // Output the first bit of the LFSR state
            char encrypted_char = c ^ keystream_bit; // XOR the character with the keystream bit
            encrypted.push_back(encrypted_char);

            // Calculate feedback bit using the specified taps
            int feedback_bit = 0;
            for (int tap : taps) {
                feedback_bit ^= state[tap];
            }

            state.pop_back();
            state.insert(state.begin(), feedback_bit); // Shift the LFSR state left and insert feedback bit
        }
        return encrypted;
    }

    std::string decrypt(const std::string& encrypted_text) {
        return encrypt(encrypted_text); // XOR encryption is symmetric
    }
};

int main() {
    try {
        if (login()) {
            int menu_choice;
            do {
                menu_choice = menu();
                switch (menu_choice) {
                case 1:
                    change();
                    break;
                case 2:
                    add();
                    break;
                case 3:
                    copy();
                    break;
                case 4:
                    del();
                    break;
                case 5:
                    show();
                    break;
                }
            } while (menu_choice != 0);
        }
    } catch (const std::exception& e) {
        cout << "Error: " << e.what() << endl;
    }
    return 0;
}

int menu() {
    cout << "\n=========================================\n";
    cout << "          PASSWORD MANAGER MENU          \n";
    cout << "=========================================\n";
    cout << "1) Change Login Password\n";
    cout << "2) Add New Platform Credentials\n";
    cout << "3) Copy Credentials to Clipboard\n";
    cout << "4) Delete Platform Credentials\n";
    cout << "5) Show All Stored Platforms\n";
    cout << "0) Exit\n";
    cout << "-----------------------------------------\n";
    cout << "Enter your choice: ";

    int choice;
    cin >> choice;

    if (cin.fail() || choice < 0 || choice > 5) {
        cin.clear(); // Clear the error flag
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
        cout << "\n[ERROR] Invalid choice. Please try again.\n";
        return menu(); // Recursively call to prompt again
    }

    return choice;
}

bool login() {
    Login log(taps, init_state);
    std::string password, correct, value;

    if (std::filesystem::exists("enter")) {
        std::ifstream fin("enter", std::ios::binary);
        getline(fin, value); // Read encrypted value
        fin.close();

        correct = log.decrypt(value);

        int attempts = 0;
        while (attempts < 3) {
            password= get_password("Enter your password: ");
            if (password == correct) {
                return true;
            }
            cout << "Wrong password. Try again.\n";
            attempts++;
        }
        return false;
    } else {
        cout << "No existing password found. Create a new password: ";
        cin >> password;
        if (!password.empty()) {
            std::string encrypted = log.encrypt(password);
            std::ofstream fout("enter", std::ios::binary);
            fout << encrypted;
            fout.close();

#ifdef _WIN32
            DWORD attributes = GetFileAttributes("enter");
            SetFileAttributes("enter", attributes | FILE_ATTRIBUTE_HIDDEN);
#endif
            return true;
        }
    }
    return false;
}

void change() {
    Login log(taps, init_state);
    std::string new_password;

    cout << "Enter the new login password (or 0 to cancel): ";
    cin >> new_password;
    if (new_password != "0") {
        std::ofstream fout("enter", std::ofstream::out | std::ofstream::trunc);
        fout << log.encrypt(new_password);
        fout.close();
        cout << "Password successfully updated.\n";
    } else {
        cout << "Password change canceled.\n";
    }
}



std::string get_password(const std::string& prompt) {
   
    struct termios oldt, newt;
    std::string input;

    // Display prompt
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

void add() {
    Login log(taps, init_state);
    std::string platform_name, username, password;

    cout << "Platform data successfully added and encrypted.\n";

    cout << "\n=========================================\n";
    cout << "         ADD NEW PLATFORM CREDENTIALS    \n";
    cout << "=========================================\n";

    cout << "Enter the platform name (or 0 to cancel): ";
    cin >> platform_name;
    if (platform_name == "0") {
        cout << "\n[INFO] Add operation canceled.\n";
        return;
    }
    
    
    if (std::filesystem::exists(platform_name)) {
        cout << "\n[ERROR] A record for \"" << platform_name << "\" already exists.\n";
        return;
    }



    cout << "Enter platform's username: ";
    cin >> username;
    password = get_password("Enter platform's password: ");

    username = log.encrypt(username);
    password = log.encrypt(password);

    std::ofstream fout(platform_name, std::ios::binary);
    fout << username << "\n" << password;
    fout.close();

#ifdef _WIN32
    DWORD attributes = GetFileAttributes(filename.c_str());
    SetFileAttributes(filename.c_str(), attributes | FILE_ATTRIBUTE_HIDDEN);
#endif

    cout << "\n[SUCCESS] Credentials for \"" << platform_name << "\" were added successfully.\n";
}


void del() {
    std::string platform_name;

    cout << "Enter platform's name to delete (or 0 to cancel): ";
    cin >> platform_name;
    if (platform_name == "0") {
        cout << "Delete operation canceled.\n";
        return;
    }

    cout << "Are you sure you want to delete \"" << platform_name << "\"? (y/n): ";
    char confirm;
    cin >> confirm;

    if (tolower(confirm) == 'y') {
        if (std::filesystem::exists(platform_name)) {
            std::filesystem::remove(platform_name);
            cout << "Record successfully deleted.\n";
        } else {
            cout << "Record does not exist.\n";
        }
    } else {
        cout << "Delete operation canceled.\n";
    }
}


void show() {
    
    std::string path;
    cout << "\n=========================================\n";
    cout << "        SHOW ALL STORED RECORDS          \n";
    cout << "=========================================\n";

    cout << "Enter the directory path to scan for records: ";
    cin >> path;

    // Check if the directory exists
    if (!std::filesystem::exists(path) || !std::filesystem::is_directory(path)) {
        cout << "\n[ERROR] Invalid directory path. Please try again.\n";
        return;
    }

    cout << "\n=========================================\n";
    cout << "         RECORDS IN DIRECTORY            \n";
    cout << "=========================================\n";

    int file_count = 0;
    const int page_size = 10; // Number of files to show per page

    for (const auto& file : std::filesystem::directory_iterator(path)) {
        if (file.is_regular_file()) { // Only display files
            cout << ++file_count << ") " << file.path().filename().string() << endl;

            // Pause after every `page_size` files
            if (file_count % page_size == 0) {
                cout << "\n[INFO] Press Enter to show more...\n";
                cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                cin.get();
            }
        }
    }

    if (file_count == 0) {
        cout << "\n[INFO] No files found in the specified directory.\n";
    } else {
        cout << "\n=========================================\n";
        cout << "[INFO] End of records. Press Enter to return to the menu.\n";
        cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        cin.get();
    }
}



void copy() {
    Login dec(taps, init_state);
    std::ifstream fin;
    std::string platform_name, encrypted_value, decrypted_value;

    cout << "\n=========================================\n";
    cout << "         COPY PLATFORM CREDENTIALS       \n";
    cout << "=========================================\n";

    cout << "Enter the platform name (or 0 to cancel): ";
    cin >> platform_name;

    if (platform_name == "0") {
        cout << "\n[INFO] Copy operation canceled.\n";
        return;
    }

    if (!std::filesystem::exists(platform_name)) {
        cout << "\n[ERROR] No record found for \"" << platform_name << "\".\n";
        return;
    }

    fin.open(platform_name, std::ios::binary);
    if (!fin) {
        cout << "\n[ERROR] Failed to open the record file.\n";
        return;
    }

    cout << "\n[INFO] Decrypted credentials for \"" << platform_name << "\":\n";
    while (getline(fin, encrypted_value)) {
        decrypted_value = dec.decrypt(encrypted_value);
        cout << decrypted_value << "\n";
    }

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
                cout << "\n[SUCCESS] Credentials copied to clipboard.\n";
            } else {
                cout << "\n[ERROR] Failed to copy to clipboard. Ensure xclip is installed.\n";
            }
        #endif
    #endif
    fin.close();
}
