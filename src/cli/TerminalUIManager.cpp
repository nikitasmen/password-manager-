#include "TerminalUIManager.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <iostream>

#include "../config/GlobalConfig.h"
#include "../core/clipboard.h"
#include "../core/terminal_ui.h"
#include "../updater/AppUpdater.h"
#include "../utils/EncryptionUtils.h"
#include "../vault/Crypto.h"

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
    connector();
    create_ = !vault->exists();
}

void TerminalUIManager::connector() {
    std::string detail;
    BoardState state = checkBoard(detail);
    while (state != BoardState::Connected) {
        header("Connect to your ESP32");
        std::cout << (state == BoardState::Unreachable ? danger(detail) : detail) << "\n\n";
        if (state == BoardState::NotPaired)
            std::cout << "To pair: press " << bold("BOOT") << " on the board (it shows a code), then press "
                      << accent("p") << " here.\n\n";
        std::cout << muted(ConfigManager::getInstance().getConfig().localCopy
                               ? "Without the board, the app uses this computer's copy and syncs later."
                               : "Device-only mode: without the board there's no vault to open.")
                  << "\n\n"
                  << legend({{"p", "pair"}, {"a", "change address"}, {"r", "check again"}, {"Enter", "continue without it"}})
                  << "\n";
        std::string in = readLine("> ");
        if (in.empty()) return;
        if (in == "a") {
            setBoardHost(readLine("Board address (the IP on its screen): "));
        } else if (in == "p") {
            const std::string def = defaultDeviceName();
            std::string name = readLine("Name for this computer " + muted("[" + def + "]") + ": ");
            if (name.empty()) name = def;
            const std::string code = normalizePairCode(readLine("Code on the board: "));
            if (!validDeviceName(name) || code.empty()) {
                message_ = danger(code.empty() ? "The code on the board has 16 characters."
                                               : "Use 1-20 characters of a-z, 0-9 and - for the name.");
                continue;
            }
            std::cout << "Now press BOOT on the board to approve '" << name << "' (within a minute)..." << std::flush;
            try {
                std::string why;
                const std::string host = ConfigManager::getInstance().getConfig().espHost;
                if (!savePairing(pairWithBoard(host, kPairPort, name, code), why)) throw PairError(why);
                message_ = accent("Paired as " + name + ".");
            } catch (const std::exception& e) {
                message_ = danger(e.what());
                continue;
            }
        } else if (in != "r") {
            continue;
        }
        state = checkBoard(detail);
    }
    if (message_.empty() && detail.size()) message_ = accent("Connected to the ESP32.");
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
        if (hasPin() && !usePassword_) {
            std::string pin = readSecret("PIN " + muted("(or m for the master password)") + ": ");
            if (pin == "m") {
                usePassword_ = true;
                attempt--;  // switching isn't a failed attempt
                continue;
            }
            if (loginWithPin(pin)) return true;
            continue;
        }
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

bool TerminalUIManager::loginWithPin(const std::string& pin) {
    std::cout << muted("Unlocking...") << std::flush;
    std::string msg;
    const PinResult r = safeUnlockWithPin(pin, msg);
    isLoggedIn = r == PinResult::Unlocked;
    if (!isLoggedIn) message_ = danger(msg);
    if (r != PinResult::Unlocked && r != PinResult::Wrong) usePassword_ = true;
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
        keys.insert(keys.end(), {{"n", "new"}, {"/text", "search"}, {"p", "master password"}});
        if (pinHost()) keys.push_back({"k", "PIN"});
        keys.push_back({"d", "hosts & devices"});
        keys.insert(keys.end(), {{"u", "update"}, {"l", "lock"}, {"q", "quit"}});
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
        } else if (in == "k" && pinHost()) {
            pinScreen();
        } else if (in == "d") {
            hostsScreen();
        } else if (in == "u") {
            updateApp();
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

void TerminalUIManager::updateApp() {
    AppUpdater updater;
    std::cout << muted("Checking GitHub for a newer version...") << std::endl;
    bool ok = false;
    std::string error;
    VersionInfo latest;
    updater.checkForUpdates([&](bool success, const std::string& message, const VersionInfo& v) {
        ok = success;
        error = message;
        latest = v;
    });
    const std::string current = VersionInfo::getCurrentVersion();
    if (!ok) {
        message_ = danger(error);
        return;
    }
    if (!latest.isNewerThan(current)) {
        message_ = accent("You have the latest version (" + current + ").");
        return;
    }
    if (const std::string managed = AppUpdater::packageManagerUpgradeCommand(); !managed.empty()) {
        message_ = accent(latest.version + " is out.") + " " + muted("Update with: " + managed);
        return;
    }
    if (readLine("Update " + current + " to " + latest.version + "? [y/N] ") != "y") return;
    updater.downloadUpdate(
        latest, [](int percent, const std::string&) { std::cout << "\r" << percent << "%" << std::flush; },
        [&](bool success, const std::string& message) {
            std::cout << "\n";
            message_ = success ? accent("Updated to " + latest.version + ". Restart the app to use it.") : danger(message);
        });
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
    std::cout << "Your other devices will ask for the new password after their next sync.\n\n";
    std::string current = readSecret("Current master password: ");
    if (current.empty()) return;
    std::string pw = readSecret("New master password: ");
    std::string repeat = readSecret("Repeat the new one: ");
    std::string error;
    message_ = safeChangeMasterPassword(current, pw, repeat, error)
                   ? accent("Master password changed.") + " " + muted("Your other devices will ask for it after their next sync.")
                   : danger(error + " Nothing was changed.");
    vaultcrypto::wipe(current), vaultcrypto::wipe(pw), vaultcrypto::wipe(repeat);
}

void TerminalUIManager::pinScreen() {
    header("PIN unlock");
    std::cout << "Unlock this computer with a PIN instead of the master password. The ESP32 checks the PIN and allows\n"
              << "5 wrong tries; after that the master password is needed again. The PIN only works while the board\n"
              << "is reachable.\n\n";
    if (hasPin()) {
        std::cout << "A PIN is set on this computer.\n\n" << legend({{"c", "change"}, {"r", "remove"}, {"Enter", "back"}}) << "\n";
        std::string in = readLine("> "), error;
        if (in == "r") message_ = safeRemovePin(error) ? accent("PIN removed.") : danger(error);
        if (in != "c") return;
    }
    std::string master = readSecret("Master password: ");
    if (master.empty()) return;
    std::string pin = readSecret("New PIN (at least 4 digits): ");
    std::string repeat = readSecret("Repeat the PIN: ");
    std::string error;
    message_ = safeSetPin(master, pin, repeat, error) ? accent("PIN set. Next time, unlock with it.")
                                                      : danger(error + " Nothing was changed.");
    vaultcrypto::wipe(master), vaultcrypto::wipe(pin), vaultcrypto::wipe(repeat);
}

void TerminalUIManager::hostsScreen() {
    while (isLoggedIn) {
        header("Hosts");
        std::cout
            << "Hosts keep a copy of the vault for your devices to sync with: the ESP32 board, or a computer that\n"
            << "runs pwvault --serve. Each network has one; this computer syncs with whichever it can reach.\n\n";
        std::vector<std::string> rows;
        for (const PairedHost& h : hosts_)
            rows.push_back(bold(h.address) + "  " + hostRoleName(h.role) + "  " + muted(hostStatusText(h)));
        if (rows.empty()) std::cout << muted("None yet: this computer keeps the vault on its own.") << "\n";
        printEntries(rows);
        std::vector<std::pair<std::string, std::string>> keys;
        const std::string range = hosts_.size() == 1 ? "1" : "1-" + std::to_string(hosts_.size());
        if (!hosts_.empty()) keys.insert(keys.end(), {{range, "devices"}, {"f " + range, "forget"}});
        if (!deviceOnly_) keys.push_back({"a", "add a host"});
        keys.push_back({"Enter", "back"});
        std::cout << "\n" << legend(keys) << "\n";

        std::string in = readLine("> "), error;
        if (in.empty()) return;
        if (lower(in) == "a" && !deviceOnly_) {
            std::cout << "\nOn the host: press BOOT on the board (or open pairing on the computer). It shows a code.\n";
            const std::string address = readLine("Host address (as it shows it; add :port if it isn't the board): ");
            const std::string def = defaultDeviceName();
            std::string name = readLine("Name for this computer " + muted("[" + def + "]") + ": ");
            if (name.empty()) name = def;
            const std::string code = normalizePairCode(readLine("Code on the host: "));
            if (!validDeviceName(name) || code.empty()) {
                message_ = danger(code.empty() ? "The code has 16 characters."
                                               : "Use 1-20 characters of a-z, 0-9 and - for the name.");
                continue;
            }
            std::cout << "Now approve '" << name << "' on the host (BOOT on the board), within a minute..."
                      << std::flush;
            message_ = safeAddHost(address, name, code, error) ? accent("Paired with " + address + ".") : danger(error);
            continue;
        }
        const bool forget = in.size() > 2 && lower(in).rfind("f ", 0) == 0;
        int n = std::atoi(in.c_str() + (forget ? 2 : 0));
        if (n < 1 || n > static_cast<int>(hosts_.size())) {
            message_ = danger("Type a number from the list, or f and a number.");
            continue;
        }
        const PairedHost h = hosts_[n - 1];
        if (!forget) {
            devicesScreen(h);
            continue;
        }
        std::cout << "\nForget " << bold(h.address) << "? This computer stops syncing with it and deletes its "
                  << "certificate for it. The vault on this computer stays.\n";
        const std::string how =
            lower(readLine("Type r to ask the host to revoke this computer first (approve it there), "
                           "f to just forget it, Enter to cancel: "));
        if (how != "r" && how != "f") continue;
        message_ = safeForgetHost(h.id, how == "r", error) ? accent("Forgot " + h.address + ".") : danger(error);
    }
}

void TerminalUIManager::devicesScreen(const PairedHost& host) {
    while (isLoggedIn) {
        std::string error;
        EspStore::Storage storage;
        auto devices = safeListDevices(*host.store, error, &storage);
        if (!devices) {
            message_ = danger(error);
            return;
        }
        header("Devices on " + host.address);
        std::cout << muted(storageText(storage)) << "\n\n";
        std::vector<std::string> rows;
        for (const auto& d : *devices)
            rows.push_back(bold(d.name) + (d.thisDevice ? " " + accent("(this computer)") : "") + "  " +
                           muted(lastSeenText(d.lastSeen)));
        printEntries(rows);
        std::cout << "\n"
                  << muted("To add a phone, type a and scan the code with the pwvault app. On a computer, run "
                            "esp32/pki.sh pair <name> instead.") << "\n\n"
                  << legend({{"a", "add a device"}, {"r 1-" + std::to_string(devices->size()), "revoke"}, {"Enter", "back"}})
                  << "\n";

        std::string in = readLine("> ");
        if (in.empty()) return;
        if (lower(in) == "a") {
            auto invite = safeOpenPairing(*host.store, error);
            if (!invite) {
                message_ = danger(error);
                continue;
            }
            const std::string& c = invite->code;
            std::cout << "\n" << qrText(invite->qr) << "\n"
                      << "Open pwvault on the phone and scan this code, then press BOOT on the board to let it in.\n"
                      << muted("Code " + c.substr(0, 4) + "-" + c.substr(4, 4) + "-" + c.substr(8, 4) + "-" + c.substr(12) +
                               ", open for " + std::to_string(invite->seconds / 60) + " min.") << "\n\n";
            readLine("Press Enter when you're done. ");
            continue;
        }
        int n = in.size() > 2 && in.rfind("r ", 0) == 0 ? std::atoi(in.c_str() + 2) : 0;
        if (n < 1 || n > static_cast<int>(devices->size())) {
            message_ = danger("Type r and a number from the list, e.g. r 2.");
            continue;
        }
        const EspStore::Device d = (*devices)[n - 1];
        std::cout << "\nRevoke " << bold(d.name) << "? It loses access to the vault until it is paired again.\n";
        if (d.thisDevice) std::cout << danger("That's this computer: you'll be locked out here.") << "\n";
        if (lower(readLine("Type yes to revoke: ")) != "yes") continue;
        std::cout << "Press BOOT on the board to confirm (within a minute)..." << std::flush;
        message_ = safeRevokeDevice(*host.store, d.name, error) ? accent("Revoked " + d.name + ".") : danger(error);
    }
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
