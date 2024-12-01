#include <vector>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <cstring>

#ifdef _WIN32
    #include <Windows.h>
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
    int choice;
    cout << "\n1) Change login password\n2) Add username/password\n3) Copy username/password to clipboard\n";
    cout << "4) Delete username/password\n5) Show all\nEnter 0 to exit\n:: ";
    cin >> choice;
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
            cout << "Enter login password: ";
            cin >> password;
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

void add() {
    Login log(taps, init_state);
    std::string platform_name, username, password;

    cout << "Enter platform's name (or 0 to cancel): ";
    cin >> platform_name;
    if (platform_name == "0") {
        cout << "Add operation canceled.\n";
        return;
    }

    std::string filename = platform_name;
    if (std::filesystem::exists(filename)) {
        cout << "File already exists. Unable to add new platform.\n";
        return;
    }

    cout << "Enter platform's username: ";
    cin >> username;
    cout << "Enter platform's password: ";
    cin >> password;

    username = log.encrypt(username);
    password = log.encrypt(password);

    std::ofstream fout(filename, std::ios::binary);
    fout << username << "\n" << password;
    fout.close();

#ifdef _WIN32
    DWORD attributes = GetFileAttributes(filename.c_str());
    SetFileAttributes(filename.c_str(), attributes | FILE_ATTRIBUTE_HIDDEN);
#endif

    cout << "Platform data successfully added and encrypted.\n";
}

void del() {
    std::string platform_name;

    cout << "Enter platform's name to delete (or 0 to cancel): ";
    cin >> platform_name;
    if (platform_name == "0") {
        cout << "Delete operation canceled.\n";
        return;
    }

    std::string filename = platform_name;
    if (std::filesystem::exists(filename)) {
        std::filesystem::remove(filename);
        cout << "Record successfully deleted.\n";
    } else {
        cout << "Record does not exist.\n";
    }
}


void show() {
    std::string path;
    cout << "Enter the directory path to scan for records: ";
    cin >> path;

    // Check if directory exists
    if (!std::filesystem::exists(path) || !std::filesystem::is_directory(path)) {
        cout << "Invalid directory path. Please try again.\n";
        return;
    }

    cout << "Listing files in the directory:\n";
    for (const auto& file : std::filesystem::directory_iterator(path)) {
        if (file.is_regular_file()) { // Only display files
            cout << file.path().filename().string() << endl;
        }
    }

    // system("pause");
}


void copy() {
    Login dec(taps, init_state);
    std::ifstream fin;
    std::string platform_name, encrypted_value, decrypted_value;

    cout << "Enter platform's name you want to copy (or 0 to cancel): ";
    cin >> platform_name;

    if (platform_name == "0") {
        cout << "Copy operation canceled.\n";
        return;
    }

    std::string filename = platform_name;

    // Check if file exists
    if (!std::filesystem::exists(filename)) {
        cout << "Record does not exist.\n";
        return;
    }

    // Read the file
    fin.open(filename, std::ios::binary);
    if (!fin) {
        cout << "Failed to open the file.\n";
        return;
    }

    cout << "Decrypted data:\n";
    while (getline(fin, encrypted_value)) {
        decrypted_value = dec.decrypt(encrypted_value);
        cout << decrypted_value << "\n";

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
            cout << "Password copied to clipboard.\n";
        } else {
            cout << "Failed to copy to clipboard. Ensure xclip is installed.\n";
        }
    #endif
#endif
    }

    fin.close();
}