#include "TerminalUIManager.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <iostream>

#include "../config/GlobalConfig.h"
#include "../core/clipboard.h"
#include "../core/terminal_ui.h"
#include "../utils/EncryptionUtils.h"

using namespace term;

namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::string now(const char* fmt) {
    std::time_t t = std::time(nullptr);
    char buf[40];
    std::strftime(buf, sizeof buf, fmt, std::localtime(&t));
    return buf;
}

// "n new   /text search   q quit": keys in the accent, words muted
std::string legend(const std::vector<std::pair<std::string, std::string>>& keys) {
    std::string out;
    for (const auto& [key, what] : keys) out += (out.empty() ? "" : "   ") + accent(key) + " " + muted(what);
    return out;
}

std::string pad(const std::string& s, size_t w) {
    size_t v = visibleWidth(s);
    return v >= w ? s : s + std::string(w - v, ' ');
}

// Numbered list in as many columns as fit: the numbers are what you type to open an entry
void printEntries(const std::vector<std::string>& items) {
    size_t longest = 0;
    for (const auto& s : items) longest = std::max(longest, visibleWidth(s));
    const size_t numW = std::to_string(items.size()).size();
    const size_t colW = numW + 2 + longest + 4;
    const size_t cols = items.size() <= 15 ? 1 : std::max<size_t>(1, std::min<size_t>(4, (width() - 2) / colW));
    const size_t rows = (items.size() + cols - 1) / cols;
    for (size_t r = 0; r < rows; r++) {
        std::string line = "  ";
        for (size_t c = 0; c < cols; c++) {
            size_t i = c * rows + r;
            if (i >= items.size()) break;
            std::string n = std::to_string(i + 1);
            line += pad(muted(std::string(numW - n.size(), ' ') + n) + "  " + items[i], colW);
        }
        std::cout << line << "\n";
    }
}

CipherAlg askCipher(CipherAlg current) {
    std::cout << muted("Encryption") << "\n";
    const auto& all = allCiphers();
    for (size_t i = 0; i < all.size(); i++)
        std::cout << "  " << muted(std::to_string(i + 1)) << "  " << encryption_utils::getDisplayName(all[i])
                  << (all[i] == current ? muted("  (Enter keeps this)") : "") << "\n";
    std::string in = readLine("> ");
    if (in.empty()) return current;
    int i = std::atoi(in.c_str());
    return i >= 1 && i <= static_cast<int>(all.size()) ? all[i - 1] : current;
}

}  // namespace

TerminalUIManager::TerminalUIManager(const std::string& dataPath) : UIManager(dataPath) {
}

void TerminalUIManager::initialize() {
    create_ = !vault->exists();
}

void TerminalUIManager::header(const std::string& state) {
    clear();
    const AppConfig& c = ConfigManager::getInstance().getConfig();
    using S = VaultService::SyncStatus;
    const S s = vault->lastSyncStatus();
    std::string where = c.espHost.empty() ? muted("Vault on this computer")
                        : !c.localCopy    ? (s == S::Offline ? danger("ESP32 at " + c.espHost + " is unreachable")
                                                             : muted("Vault on the ESP32 at " + c.espHost + ", nothing stored here"))
                        : s == S::Ok      ? muted("Synced with the ESP32 at " + c.espHost)
                        : s == S::Offline ? muted("ESP32 offline, working on this computer's copy")
                        : s == S::Error   ? danger("ESP32 sync error: " + vault->lastSyncError())
                                          : muted("Vault on this computer, syncs with the ESP32 at " + c.espHost);
    auto panel = oled(now("%H:%M"));
    std::vector<std::string> side = {"", bold(state), where, ""};
    for (size_t i = 0; i < panel.size(); i++) std::cout << panel[i] << "  " << side[i] << "\n";
    std::cout << "\n";
    if (!message_.empty()) {
        std::cout << message_ << "\n\n";
        message_.clear();
    }
}

int TerminalUIManager::show() {
    try {
        while (!quit_) {
            if (!unlockScreen()) return 1;
            home();
            vault->lock();
            isLoggedIn = false;
        }
    } catch (const std::exception& e) {
        std::cerr << danger("Error: ") << e.what() << "\n";
        return 1;
    }
    clear();
    return 0;
}

// ---- unlock / create ----

bool TerminalUIManager::unlockScreen() {
    for (int attempt = 0; attempt < kMaxLoginAttempts; attempt++) {
        header(create_ ? "Create your vault" : "Locked");
        if (create_) {
            std::string pw = readSecret("Master password: ");
            std::string again = readSecret("Repeat it: ");
            if (setupPassword(pw, again, encryption_utils::getDefault())) return true;
            attempt = -1;  // mistakes while creating don't count as failed unlocks
            continue;
        }
        std::cout << "Unlock your vault to see your passwords.\n\n";
        if (login(readSecret("Master password: "))) return true;
    }
    header("Locked");
    std::cout << danger("Too many wrong passwords.") << " Start the app again to retry.\n";
    return false;
}

bool TerminalUIManager::login(const std::string& password) {
    std::cout << muted("Unlocking...") << std::flush;
    try {
        isLoggedIn = vault->unlock(password);
    } catch (const std::exception& e) {
        message_ = danger(e.what());
        return false;
    }
    if (!isLoggedIn) message_ = danger("That's not the master password.");
    return isLoggedIn;
}

bool TerminalUIManager::setupPassword(const std::string& newPassword, const std::string& confirmPassword, CipherAlg alg) {
    const int minLen = ConfigManager::getInstance().getConfig().minPasswordLength;
    if (static_cast<int>(newPassword.size()) < minLen) {
        message_ = danger("Use at least " + std::to_string(minLen) + " characters.");
        return false;
    }
    if (newPassword != confirmPassword) {
        message_ = danger("The two passwords don't match.");
        return false;
    }
    try {
        vault->create(newPassword, alg);
    } catch (const std::exception& e) {
        message_ = danger(e.what());
        return false;
    }
    isLoggedIn = true;
    create_ = false;
    message_ = accent("Vault created.");
    return true;
}

// ---- home: the entry list ----

void TerminalUIManager::home() {
    std::string filter;
    while (isLoggedIn) {
        std::vector<std::string> all = safeGetPlatforms(), shown;
        for (const auto& p : all)
            if (filter.empty() || lower(p).find(lower(filter)) != std::string::npos) shown.push_back(p);

        header(std::to_string(all.size()) + (all.size() == 1 ? " entry" : " entries"));
        if (all.empty()) {
            std::cout << "Your vault is empty. Press " << accent("n") << " to add your first password.\n";
        } else if (shown.empty()) {
            std::cout << "Nothing matches \"" << filter << "\". " << muted("Type / to clear the search.") << "\n";
        } else {
            if (!filter.empty()) std::cout << muted("Matching \"" + filter + "\"") << "\n";
            printEntries(shown);
        }
        std::vector<std::pair<std::string, std::string>> keys;
        if (!shown.empty()) keys.push_back({shown.size() == 1 ? "1" : "1-" + std::to_string(shown.size()), "open"});
        keys.insert(keys.end(), {{"n", "new"}, {"/text", "search"}, {"p", "master password"}, {"l", "lock"}, {"q", "quit"}});
        std::cout << "\n" << legend(keys) << "\n";

        std::string in = readLine("> ");
        if (in == "q") {
            quit_ = true;
            return;
        }
        if (in == "l") return;
        if (in == "n") {
            newEntry();
        } else if (in == "p") {
            changeMasterPassword();
        } else if (!in.empty() && in[0] == '/') {
            filter = in.substr(1);
        } else if (!in.empty()) {
            // a number from the list, or the start of a name
            int n = std::all_of(in.begin(), in.end(), ::isdigit) ? std::atoi(in.c_str()) : 0;
            std::string pick;
            if (n >= 1 && n <= static_cast<int>(shown.size())) pick = shown[n - 1];
            for (const auto& p : shown)
                if (pick.empty() && lower(p).rfind(lower(in), 0) == 0) pick = p;
            if (pick.empty())
                message_ = danger("No entry \"" + in + "\".") + " " + muted("Type a number from the list or a name.");
            else
                viewCredential(pick);
        }
    }
}

// ---- one entry ----

void TerminalUIManager::viewCredential(const std::string& platform) {
    bool revealed = false;
    while (isLoggedIn) {
        auto c = safeGetCredentials(platform);
        if (!c) {
            message_ = vault->lastSyncStatus() == VaultService::SyncStatus::Offline
                           ? danger(syncStatusText() + ".")
                           : danger("No entry \"" + platform + "\".");
            return;
        }
        header(c->platform);
        std::string masked;
        for (size_t i = 0; i < std::min<size_t>(c->password.size(), 18); i++) masked += "•";
        std::cout << "  " << pad(muted("Username"), 14) << c->username << "\n";
        std::cout << "  " << pad(muted("Password"), 14) << (revealed ? c->password : masked) << "\n";
        if (ConfigManager::getInstance().getConfig().showEncryptionInCredentials)
            std::cout << "  " << pad(muted("Encryption"), 14) << encryption_utils::getDisplayName(c->alg) << "\n";
        std::cout << "\n"
                  << legend({{"c", "copy password"},
                             {"u", "copy username"},
                             {"s", revealed ? "hide" : "show"},
                             {"e", "edit"},
                             {"d", "delete"},
                             {"Enter", "back"}})
                  << "\n";

        std::string in = readLine("> ");
        if (in.empty()) return;
        if (in == "s") {
            revealed = !revealed;
        } else if (in == "e") {
            editEntry(*c);
        } else if (in == "d") {
            if (deleteCredential(c->platform)) return;
        } else if (in == "c" || in == "u") {
            const std::string what = in == "c" ? "password" : "username";
            try {
                if (!ClipboardManager::getInstance().isAvailable()) throw ClipboardError("no clipboard tool");
                ClipboardManager::getInstance().copyToClipboard(in == "c" ? c->password : c->username);
                message_ = accent("Copied the " + what + ".");
            } catch (const std::exception&) {
                message_ = danger("Couldn't copy: no clipboard tool found.") + " " +
                           muted("Install wl-clipboard or xclip, or press s to show it.");
            }
        }
    }
}

void TerminalUIManager::newEntry() {
    header("New entry");
    std::string platform = readLine("Website or app: ");
    if (platform.empty()) return;
    std::string user = readLine("Username: ");
    std::string pw = readSecret("Password: ");
    if (pw != readSecret("Repeat password: ")) {
        message_ = danger("The two passwords don't match. Nothing was saved.");
        return;
    }
    CipherAlg alg = askCipher(encryption_utils::getDefault());
    if (addCredential(platform, user, pw, alg)) viewCredential(platform);
}

void TerminalUIManager::editEntry(const Credential& c) {
    header("Edit " + c.platform);
    std::cout << muted("Press Enter to keep a value.") << "\n\n";
    std::string user = readLine("Username " + muted("[" + c.username + "]") + ": ");
    std::string pw = readSecret("New password: ");
    if (!pw.empty() && pw != readSecret("Repeat it: ")) {
        message_ = danger("The two passwords don't match. Nothing was changed.");
        return;
    }
    CipherAlg alg = askCipher(c.alg);
    updateCredential(c.platform, user.empty() ? c.username : user, pw.empty() ? c.password : pw, alg);
}

void TerminalUIManager::changeMasterPassword() {
    header("Change master password");
    std::cout << "Your other devices will need the new password after their next sync.\n\n";
    std::string pw = readSecret("New master password: ");
    if (pw.empty()) return;
    if (pw != readSecret("Repeat it: ")) {
        message_ = danger("The two passwords don't match. Nothing was changed.");
        return;
    }
    const int minLen = ConfigManager::getInstance().getConfig().minPasswordLength;
    if (static_cast<int>(pw.size()) < minLen) {
        message_ = danger("Use at least " + std::to_string(minLen) + " characters. Nothing was changed.");
        return;
    }
    message_ = safeChangeMasterPassword(pw) ? accent("Master password changed.")
                                            : danger("Couldn't change the master password.");
}

// ---- UIManager interface ----

bool TerminalUIManager::addCredential(const std::string& platform,
                                      const std::string& username,
                                      const std::string& password,
                                      std::optional<CipherAlg> encryptionType) {
    if (!isLoggedIn) return false;
    bool ok = safeAddCredential(platform, username, password, encryptionType);
    message_ = ok ? accent("Saved " + platform + ".") : danger("Couldn't save " + platform + ". Every field is required.");
    return ok;
}

bool TerminalUIManager::updateCredential(const std::string& platform,
                                         const std::string& username,
                                         const std::string& password,
                                         std::optional<CipherAlg> encryptionType) {
    bool ok = isLoggedIn && UIManager::updateCredential(platform, username, password, encryptionType);
    message_ = ok ? accent("Saved " + platform + ".") : danger("Couldn't save " + platform + ".");
    return ok;
}

bool TerminalUIManager::deleteCredential(const std::string& platform) {
    if (!isLoggedIn) return false;
    if (!confirm(danger("Delete " + platform + "?") + " It's removed from all your devices.")) return false;
    bool ok = safeDeleteCredential(platform);
    message_ = ok ? accent("Deleted " + platform + ".") : danger("Couldn't delete " + platform + ".");
    return ok;
}

void TerminalUIManager::showMessage(const std::string&, const std::string& message, bool isError) {
    message_ = isError ? danger(message) : accent(message);
}
