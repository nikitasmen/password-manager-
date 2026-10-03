#include "GuiUIManager.h"

#include <FL/Fl.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Group.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Int_Input.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/fl_ask.H>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>

#include "../config/GlobalConfig.h"
#include "../utils/EncryptionUtils.h"
#include "Theme.h"
#include "UpdateDialog.h"
#include "Widgets.h"

using namespace theme;

namespace {

constexpr int kVaultW = 900, kVaultH = 580, kStripH = 40, kListW = 300, kPad = 32;
constexpr auto kEventTime = std::chrono::seconds(4);

// FLTK reads '@' in labels as a symbol code; user text (emails!) must show literally
std::string literal(const std::string& s) {
    std::string out;
    for (char c : s) out += c == '@' ? "@@" : std::string(1, c);
    return out;
}

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

Fl_Box* text(int x, int y, int w, int h, const std::string& label, Fl_Font font, int size, Fl_Color color) {
    auto* b = new Fl_Box(x, y, w, h);
    b->copy_label(label.c_str());
    b->labelfont(font);
    b->labelsize(size);
    b->labelcolor(color);
    b->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
    return b;
}

template <class Input>
Input* field(int x, int y, int w, int h, const char* label = nullptr) {
    auto* f = new Input(x, y, w, h);
    f->box(FLAT_FIELD);
    f->color(FL_WHITE);
    f->textfont(kSans);
    f->textsize(kValue);
    f->cursor_color(ink());
    if (label) {
        f->copy_label(label);
        f->labelsize(kSmall);
        f->labelcolor(muted());
        f->align(FL_ALIGN_TOP_LEFT);
    }
    return f;
}

Fl_Choice* choice(int x, int y, int w, int h, const char* label) {
    auto* c = new Fl_Choice(x, y, w, h, label);
    c->labelsize(kSmall);
    c->labelcolor(muted());
    c->align(FL_ALIGN_TOP_LEFT);
    c->textsize(kBody);
    c->color(FL_WHITE);
    return c;
}

// Where this machine's vault lives, in one sentence for the unlock screen
std::string whereText(const std::string& host) {
    if (host.empty()) return "Your vault is stored on this computer.";
    if (!ConfigManager::getInstance().getConfig().localCopy)
        return "Your vault lives on the host at " + host + ". Nothing is stored on this computer.";
    return "Your vault is on this computer and syncs with " + host + ".";
}

// Replace a window we may be inside the callback of: FLTK deletes the old one once that callback returns
void replaceWindow(std::unique_ptr<Fl_Double_Window>& slot, Fl_Double_Window* next) {
    if (slot) {
        slot->hide();
        Fl::delete_widget(slot.release());
    }
    slot.reset(next);
}

void runModal(Fl_Window* w) {
    w->set_modal();
    w->show();
    while (w->shown()) Fl::wait();
}

// The "Add a device" window's countdown: pairing on the board closes after 2 minutes
struct PairCountdown {
    Fl_Box* label;
    std::time_t until;
};

void tickPairCountdown(void* p) {
    auto* c = static_cast<PairCountdown*>(p);
    const long left = static_cast<long>(c->until - std::time(nullptr));
    char buf[120];
    if (left > 0) std::snprintf(buf, sizeof buf, "Pairing closes in %ld:%02ld.", left / 60, left % 60);
    else std::snprintf(buf, sizeof buf, "Pairing has closed. Close this window and add the device again.");
    c->label->copy_label(buf);
    c->label->redraw();
    if (left > 0) Fl::repeat_timeout(1.0, tickPairCountdown, p);
}

void clearClipboard(void*) {
    Fl::copy("", 0, 1);
}

}  // namespace

GuiUIManager::GuiUIManager(const std::string& dataPath) : UIManager(dataPath) {
}

GuiUIManager::~GuiUIManager() {
    Fl::remove_timeout(tick, this);
}

void GuiUIManager::on(Fl_Widget* w, std::function<void()> f) {
    callbacks_.push_back(std::move(f));
    w->callback([](Fl_Widget*, void* fn) { (*static_cast<std::function<void()>*>(fn))(); }, &callbacks_.back());
}

// ---- unlock / create ----

void GuiUIManager::initialize() {
    runConnector();
    try {
        buildUnlockWindow(!vault->exists());
    } catch (const std::exception& e) {  // e.g. device-only and the board is off
        fl_message_title("Can't open the vault");
        fl_alert("%s", e.what());
        return;
    }
    Fl::add_timeout(1.0, tick, this);
}

int GuiUIManager::show() {
    if (unlockWin_) unlockWin_->show();
    return 0;
}

void GuiUIManager::buildUnlockWindow(bool create) {
    const int W = 440, x = 28, fw = W - 2 * x;
    const bool offerPin = !create && hasPin(), pin = offerPin && !usePassword_;
    auto* w = new Fl_Double_Window(W, create ? 574 : offerPin ? 548 : 504);
    w->copy_label(create ? "Create your vault" : "Unlock your vault");
    w->color(enclosure());

    unlockOled_ = new OledPanel(x, 28, 384, 192, 3);  // the board's 128x64 screen at 3x
    int y = 244;
    text(x, y, fw, 30, create ? "Create your vault" : "Unlock your vault", kSansBold, kTitle, ink());
    y += 34;
    text(x, y, fw, 40, whereText(boardAddress()), kSans, kBody, muted());
    y += 64;
    pass1_ = field<Fl_Secret_Input>(x, y, fw, 38, pin ? "PIN" : "Master password");
    y += 60;
    pass2_ = nullptr;
    if (create) {
        pass2_ = field<Fl_Secret_Input>(x, y, fw, 38, "Repeat it");
        y += 60;
    }
    unlockError_ = text(x, y - 14, fw, 38, "", kSans, kSmall, danger());  // two lines: PIN messages are long
    y += 28;
    Fl_Button* go = button(x, y, fw, 42, create ? "Create vault" : "Unlock", Kind::Primary);
    if (offerPin) {
        Fl_Button* other = button(x, y + 52, fw, 32, pin ? "Use the master password instead" : "Use the PIN instead");
        on(other, [this] {
            usePassword_ = !usePassword_;
            buildUnlockWindow(false);
            unlockWin_->show();
        });
    }
    w->end();

    on(go, [this, create, pin] {
        unlockError_->labelcolor(muted());
        unlockError_->copy_label(create ? "Creating your vault..." : "Unlocking...");
        unlockError_->redraw();
        Fl::flush();  // deriving the key takes a moment; show that something is happening
        unlockError_->labelcolor(danger());
        if (create)
            setupPassword(pass1_->value(), pass2_->value(), encryption_utils::getDefault());
        else if (pin)
            loginWithPin(pass1_->value());
        else
            login(pass1_->value());
    });
    pass1_->when(FL_WHEN_ENTER_KEY_ALWAYS);
    on(pass1_, [this, go] {
        if (pass2_)
            pass2_->take_focus();
        else
            go->do_callback();
    });
    if (pass2_) {
        pass2_->when(FL_WHEN_ENTER_KEY_ALWAYS);
        on(pass2_, [go] { go->do_callback(); });
    }
    replaceWindow(unlockWin_, w);
    drawUnlockOled();
}

bool GuiUIManager::login(const std::string& password) {
    try {
        if (!vault->unlock(password)) {
            if (unlockError_) unlockError_->copy_label("That's not the master password.");
            if (pass1_) pass1_->value("");
            return false;
        }
    } catch (const std::exception& e) {
        if (unlockError_) unlockError_->copy_label(e.what());
        return false;
    }
    isLoggedIn = true;
    buildVaultWindow();
    return true;
}

bool GuiUIManager::loginWithPin(const std::string& pin) {
    std::string msg;
    const PinResult r = safeUnlockWithPin(pin, msg);
    if (r == PinResult::Unlocked) {
        isLoggedIn = true;
        buildVaultWindow();
        return true;
    }
    if (r != PinResult::Wrong) {  // the PIN can't work now: switch this window to the master password
        usePassword_ = true;
        buildUnlockWindow(false);
        unlockWin_->show();
    }
    if (unlockError_) unlockError_->copy_label(literal(msg).c_str());
    if (pass1_) pass1_->value("");
    return false;
}

bool GuiUIManager::setupPassword(const std::string& newPassword, const std::string& confirmPassword, CipherAlg alg) {
    const int minLen = ConfigManager::getInstance().getConfig().minPasswordLength;
    std::string problem;
    if (newPassword.empty())
        problem = "Choose a master password.";
    else if (static_cast<int>(newPassword.size()) < minLen)
        problem = "Use at least " + std::to_string(minLen) + " characters.";
    else if (newPassword != confirmPassword)
        problem = "The two passwords don't match.";
    if (!problem.empty()) {
        if (unlockError_) unlockError_->copy_label(problem.c_str());
        return false;
    }
    try {
        vault->create(newPassword, alg);
    } catch (const std::exception& e) {
        if (unlockError_) unlockError_->copy_label(e.what());
        return false;
    }
    isLoggedIn = true;
    buildVaultWindow();
    flash("vault created");
    return true;
}

// ---- vault window ----

void GuiUIManager::buildVaultWindow() {
    auto* w = new Fl_Double_Window(kVaultW, kVaultH);
    w->copy_label("Password Manager");
    w->color(enclosure());

    // The strip redraws every second (clock), so nothing may overlap it: the buttons get their own black area.
    const int kActionsW = 292;
    strip_ = new OledPanel(0, 0, kVaultW - kActionsW, kStripH, 2);
    auto* actions = new Fl_Box(kVaultW - kActionsW, 0, kActionsW, kStripH);
    actions->box(FL_FLAT_BOX);
    actions->color(oledOff());
    Fl_Button* devices = button(kVaultW - 284, 6, 84, 28, "Devices", Kind::OnOled);
    devices->tooltip("The hosts this computer syncs with, and the devices paired with each");
    on(devices, [this] { openDevices(); });
    Fl_Button* settings = button(kVaultW - 192, 6, 84, 28, "Settings", Kind::OnOled);
    Fl_Button* lock = button(kVaultW - 100, 6, 84, 28, "Lock", Kind::OnOled);
    lock->tooltip("Lock the vault: the master password is needed again");
    on(settings, [this] { openSettings(); });
    on(lock, [this] { lockVault(); });

    // left: search + entries
    auto* left = new Fl_Group(0, kStripH, kListW, kVaultH - kStripH);
    left->box(FL_FLAT_BOX);
    left->color(surface());
    search_ = field<Fl_Input>(16, kStripH + 34, kListW - 32, 36, "Search");
    search_->when(FL_WHEN_CHANGED | FL_WHEN_ENTER_KEY_ALWAYS);
    on(search_, [this] {
        refreshList();
        if (Fl::event_key() == FL_Enter && list_->size() > 0) {  // Enter opens the first match
            list_->select(1);
            list_->do_callback();
        }
    });
    list_ = new EntryList(0, kStripH + 86, kListW, kVaultH - kStripH - 86 - 66);
    list_->box(FL_FLAT_BOX);
    list_->color(surface());
    list_->scrollbar_size(8);
    on(list_, [this] {
        int i = list_->value();
        if (i <= 0) return;
        revealed_ = false;
        selected_ = list_->text(i);
        showDetail(safeGetCredentials(selected_));
    });
    Fl_Button* add = button(16, kVaultH - 54, kListW - 32, 40, "New entry", Kind::Primary);
    add->shortcut(FL_CTRL + 'n');
    add->tooltip("Ctrl+N");
    on(add, [this] { editEntry(std::nullopt); });
    left->end();

    auto* divider = new Fl_Box(kListW, kStripH, 1, kVaultH - kStripH);
    divider->box(FL_FLAT_BOX);
    divider->color(line());

    // right: the selected entry
    const int dx = kListW + 1 + kPad, dw = kVaultW - dx - kPad;
    title_ = text(dx, kStripH + 30, dw - 100, 34, "", kSansBold, kTitle, ink());
    edit_ = button(dx + dw - 84, kStripH + 32, 84, 32, "Edit");
    on(edit_, [this] {
        if (current_) editEntry(current_);
    });
    hint_ = text(dx, kStripH + 70, dw, 48, "", kSans, kBody, muted());

    const int valueX = dx + 120, row = 58, y0 = kStripH + 92;
    userLabel_ = text(dx, y0, 120, 34, "Username", kSans, kBody, muted());
    userValue_ = text(valueX, y0, dw - 120 - 94, 34, "", kSans, kValue, ink());
    copyUser_ = button(dx + dw - 84, y0 + 1, 84, 32, "Copy");
    on(copyUser_, [this] {
        if (current_) copy(current_->username, "username");
    });
    passLabel_ = text(dx, y0 + row, 120, 34, "Password", kSans, kBody, muted());
    passValue_ = text(valueX, y0 + row, dw - 120 - 188, 34, "", kMono, kValue, ink());
    passShown_ = text(valueX, y0 + row + 36, dw - 120, 30, "", kMono, kValue, ink());
    passShown_->box(FLAT_FIELD);
    passShown_->color(FL_WHITE);
    passShown_->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_CLIP);
    reveal_ = button(dx + dw - 178, y0 + row + 1, 84, 32, "Show");
    on(reveal_, [this] {
        revealed_ = !revealed_;
        showDetail(current_);
    });
    copyPass_ = button(dx + dw - 84, y0 + row + 1, 84, 32, "Copy");
    on(copyPass_, [this] {
        if (current_) copy(current_->password, "password");
    });
    algLabel_ = text(dx, y0 + 2 * row, 120, 34, "Encryption", kSans, kBody, muted());
    algValue_ = text(valueX, y0 + 2 * row, dw - 120, 34, "", kSans, kValue, ink());
    delete_ = button(dx + dw - 100, kVaultH - 54, 100, 40, "Delete", Kind::Danger);
    on(delete_, [this] {
        if (current_) deleteCredential(current_->platform);
    });
    w->end();

    replaceWindow(vaultWin_, w);
    if (unlockWin_) {  // we're inside its Unlock button's callback
        unlockWin_->hide();
        Fl::delete_widget(unlockWin_.release());
        unlockOled_ = nullptr;
        unlockError_ = nullptr;
        pass1_ = pass2_ = nullptr;
    }
    vaultWin_->show();
    search_->take_focus();
    platforms_ = safeGetPlatforms();
    refreshList();
}

void GuiUIManager::refreshList(const std::string& select) {
    const std::string query = lower(search_->value());
    if (!select.empty()) selected_ = select;
    const std::string& keep = selected_;
    list_->clear();
    int keepIndex = 0;
    for (const std::string& p : platforms_) {
        if (!query.empty() && lower(p).find(query) == std::string::npos) continue;
        list_->add(p.c_str());
        if (lower(p) == lower(keep)) keepIndex = list_->size();
    }
    if (keepIndex) {
        list_->select(keepIndex);
        showDetail(safeGetCredentials(list_->text(keepIndex)));
    } else {
        showDetail(std::nullopt);
    }
    drawStrip();
}

void GuiUIManager::showDetail(std::optional<Credential> cred) {
    current_ = std::move(cred);
    const bool has = current_.has_value();
    const bool showAlg = has && ConfigManager::getInstance().getConfig().showEncryptionInCredentials;
    for (Fl_Widget* wd : std::initializer_list<Fl_Widget*>{userLabel_, userValue_, copyUser_, passLabel_, passValue_,
                                                          reveal_, copyPass_, edit_, delete_})
        has ? wd->show() : wd->hide();
    for (Fl_Widget* wd : std::initializer_list<Fl_Widget*>{algLabel_, algValue_}) showAlg ? wd->show() : wd->hide();
    (has && revealed_) ? passShown_->show() : passShown_->hide();
    const int algY = passLabel_->y() + (has && revealed_ ? 58 + 44 : 58);  // make room under a revealed password
    algLabel_->position(algLabel_->x(), algY);
    algValue_->position(algValue_->x(), algY);

    if (has) {
        title_->copy_label(literal(current_->platform).c_str());
        hint_->copy_label("");
        userValue_->copy_label(literal(current_->username).c_str());
        std::string masked;
        for (size_t i = 0; i < std::min<size_t>(current_->password.size(), 18); i++) masked += "•";
        passValue_->copy_label(masked.c_str());
        passShown_->copy_label((" " + literal(current_->password)).c_str());
        reveal_->label(revealed_ ? "Hide" : "Show");
        algValue_->copy_label(encryption_utils::getDisplayName(current_->alg));
    } else if (platforms_.empty()) {
        title_->copy_label("Your vault is empty");
        hint_->copy_label(
            "New entry saves your first password. It's encrypted on this computer before it goes anywhere.");
    } else {
        title_->copy_label(list_->size() ? "Nothing selected" : "No matches");
        hint_->copy_label(list_->size() ? "Pick an entry on the left." : "Nothing in your vault matches that search.");
    }
    vaultWin_->redraw();
}

void GuiUIManager::lockVault() {
    vault->lock();
    isLoggedIn = false;
    current_.reset();
    selected_.clear();
    platforms_.clear();
    buildUnlockWindow(false);
    unlockWin_->show();
    if (vaultWin_) {  // we're inside its Lock button's callback
        vaultWin_->hide();
        Fl::delete_widget(vaultWin_.release());
        strip_ = nullptr;
    }
}

void GuiUIManager::copy(const std::string& value, const std::string& what) {
    Fl::copy(value.c_str(), static_cast<int>(value.size()), 1);
    const AppConfig& c = ConfigManager::getInstance().getConfig();
    Fl::remove_timeout(clearClipboard);
    if (c.autoClipboardClear) {
        Fl::add_timeout(c.clipboardTimeoutSeconds, clearClipboard);
        flash("copied " + what + ", clears in " + std::to_string(c.clipboardTimeoutSeconds) + "s");
    } else {
        flash("copied " + what);
    }
}

// ---- the OLEDs ----

void GuiUIManager::flash(const std::string& event) {
    event_ = lower(event);
    eventUntil_ = std::chrono::steady_clock::now() + kEventTime;
    drawStrip();
}

void GuiUIManager::drawStrip() {
    if (!strip_) return;
    std::string status;
    if (std::chrono::steady_clock::now() < eventUntil_) {
        status = event_;
    } else {
        const AppConfig& c = ConfigManager::getInstance().getConfig();
        auto s = vault->lastSyncStatus();
        if (!c.localCopy)
            status = s == VaultService::SyncStatus::Offline ? "host unreachable" : "device-only, on the host";
        else if (boardAddress().empty())
            status = "on this computer";
        else if (s == VaultService::SyncStatus::Ok)
            status = "synced with " + lower(boardAddress());
        else if (s == VaultService::SyncStatus::Offline)
            status = "hosts offline, local copy";
        else
            status = "sync error: " + lower(vault->lastSyncError()).substr(0, 40);
    }
    const std::string count = std::to_string(platforms_.size()) + (platforms_.size() == 1 ? " entry" : " entries");
    const int countX = strip_->columns() - 8 - 6 * static_cast<int>(count.size());
    const size_t room = static_cast<size_t>(std::max(0, (countX - 56) / 6 - 2));  // glyphs are 6 px wide
    if (status.size() > room) status = status.substr(0, room - 2) + "..";
    strip_->setText({{now("%H:%M"), 8, 6}, {status, 56, 6}, {count, countX, 6}});
}

void GuiUIManager::drawUnlockOled() {
    if (!unlockOled_) return;
    // the same layout as the board's clock screen (esp32/vault/vault.ino)
    unlockOled_->setText(
        {{now("%H:%M:%S"), 16, 8, 2}, {now("%a %d %b %Y"), 19, 32}, {pass2_ ? "new vault" : "locked", 0, 56}});
}

void GuiUIManager::tick(void* self) {
    auto* ui = static_cast<GuiUIManager*>(self);
    ui->drawUnlockOled();
    ui->drawStrip();
    Fl::repeat_timeout(1.0, tick, self);
}

// ---- dialogs ----

void GuiUIManager::editEntry(const std::optional<Credential>& existing) {
    const size_t mark = callbacks_.size();
    const int W = 460, x = 28, fw = W - 2 * x;
    auto* w = new Fl_Double_Window(W, 420);
    w->copy_label(existing ? ("Edit " + existing->platform).c_str() : "New entry");
    w->color(enclosure());
    text(x, 22, fw, 30, existing ? "Edit " + literal(existing->platform) : "New entry", kSansBold, 20, ink());
    auto* platform = field<Fl_Input>(x, 90, fw, 36, "Website or app");
    auto* user = field<Fl_Input>(x, 152, fw, 36, "Username");
    auto* pass = field<Fl_Secret_Input>(x, 214, fw, 36, "Password");
    Fl_Choice* alg = choice(x, 276, fw, 36, "Encrypt with");
    for (CipherAlg a : allCiphers()) alg->add(encryption_utils::getDisplayName(a));
    alg->value(encryption_utils::toDropdownIndex(existing ? existing->alg : encryption_utils::getDefault()));
    if (existing) {
        platform->value(existing->platform.c_str());
        platform->deactivate();  // the name is the entry's identity; renaming = a new entry
        user->value(existing->username.c_str());
        pass->value(existing->password.c_str());
    }
    Fl_Box* error = text(x, 322, fw, 22, "", kSans, kSmall, danger());
    Fl_Button* cancel = button(W - x - 208, 360, 100, 38, "Cancel");
    Fl_Button* save = button(W - x - 100, 360, 100, 38, existing ? "Save" : "Add entry", Kind::Primary);
    save->shortcut(FL_Enter);
    w->end();

    on(cancel, [w] { w->hide(); });
    on(save, [&, this] {
        std::string p = platform->value(), u = user->value(), pw = pass->value();
        if (p.empty() || u.empty() || pw.empty()) {
            error->copy_label("Fill in all three fields.");
            return;
        }
        CipherAlg a = encryption_utils::fromDropdownIndex(alg->value());
        if (existing ? updateCredential(p, u, pw, a) : addCredential(p, u, pw, a))
            w->hide();
        else
            error->copy_label("Couldn't save this entry. The terminal has the details.");
    });
    (existing ? static_cast<Fl_Widget*>(user) : platform)->take_focus();
    runModal(w);
    delete w;
    callbacks_.resize(mark);
}

void GuiUIManager::openSettings() {
    const size_t mark = callbacks_.size();
    const AppConfig& c = ConfigManager::getInstance().getConfig();
    const int W = 520, x = 28, fw = W - 2 * x;
    const int pinRow = pinHost() ? 56 : 0;  // PIN unlock needs a dedicated host
    auto* w = new Fl_Double_Window(W, 640 + pinRow);
    w->copy_label("Settings");
    w->color(enclosure());
    text(x, 22, fw, 30, "Settings", kSansBold, 20, ink());

    text(x, 70, fw, 22, "Hosts", kSansBold, kBody, ink());
    text(x, 96, fw, 66,
         hosts_.empty() ? "None: the vault is on this computer only. Add one in Devices."
                        : "Synced with " + boardAddress() + (hosts_.size() > 1 ? " and others" : "") +
                              ". Add or forget hosts in Devices.",
         kSans, kSmall, muted());
    auto* localCopy = new Fl_Check_Button(x, 166, fw, 28, " Keep a copy of the vault on this computer");
    localCopy->value(c.localCopy);
    text(x + 26, 192, fw - 26, 40,
         "When off, every read goes to the ESP32 and nothing is stored here, but you need the ESP32 to reach your "
         "passwords.",
         kSans, kSmall, muted());

    text(x, 250, fw, 22, "Entries", kSansBold, kBody, ink());
    Fl_Choice* cipher = choice(x, 298, fw, 36, "Encrypt new entries with");
    for (CipherAlg a : allCiphers()) cipher->add(encryption_utils::getDisplayName(a));
    cipher->value(encryption_utils::toDropdownIndex(c.defaultCipher));
    auto* showAlg = new Fl_Check_Button(x, 344, fw, 28, " Show each entry's encryption");
    showAlg->value(c.showEncryptionInCredentials);
    auto* autoClear = new Fl_Check_Button(x, 378, fw - 120, 28, " Clear copied passwords after (seconds)");
    autoClear->value(c.autoClipboardClear);
    auto* clearAfter = field<Fl_Int_Input>(x + fw - 100, 374, 100, 34);
    clearAfter->value(std::to_string(c.clipboardTimeoutSeconds).c_str());

    text(x, 430, fw, 22, "App", kSansBold, kBody, ink());
    Fl_Choice* mode = choice(x, 478, 240, 36, "Open in");
    mode->add("Window|Terminal|Window if available");
    mode->value(c.defaultUIMode == "gui" ? 0 : (c.defaultUIMode == "tui" || c.defaultUIMode == "cli") ? 1 : 2);
    Fl_Button* updates = button(x + fw - 170, 478, 170, 36, "Check for updates");
    on(updates, [this] {
        if (!updateDialog_) updateDialog_ = std::make_unique<UpdateDialog>();
        updateDialog_->show();
    });

    text(x, 534, fw - 230, 36, "Master password", kSansBold, kBody, ink());
    Fl_Button* master = button(x + fw - 220, 534, 220, 36, "Change master password");
    on(master, [this] { changeMasterPassword(); });
    if (pinHost()) {
        Fl_Box* pinText = text(x, 590, fw - 230, 36, "", kSansBold, kBody, ink());
        Fl_Button* setPin = button(x + fw - 220, 590, 106, 36, "");
        Fl_Button* removePin = button(x + fw - 106, 590, 106, 36, "Remove PIN");
        auto refresh = [=, this] {
            pinText->copy_label(hasPin() ? "PIN unlock: on" : "PIN unlock: off");
            setPin->copy_label(hasPin() ? "Change PIN" : "Set PIN");
            hasPin() ? removePin->activate() : removePin->deactivate();
            pinText->window()->redraw();
        };
        on(setPin, [=, this] {
            setPinDialog();
            refresh();
        });
        on(removePin, [=, this] {
            if (fl_choice("Remove the PIN? You'll unlock with the master password.", "Cancel", "Remove", nullptr) != 1)
                return;
            std::string error;
            if (!safeRemovePin(error)) fl_alert("%s", literal(error).c_str());
            refresh();
        });
        refresh();
    }

    const int footY = 590 + pinRow;
    text(x, footY, 150, 38, "Version " + c.version, kSans, kSmall, muted());  // footer, left of Cancel/Save
    Fl_Button* cancel = button(W - x - 208, footY, 100, 38, "Cancel");
    Fl_Button* save = button(W - x - 100, footY, 100, 38, "Save", Kind::Primary);
    w->end();

    on(cancel, [w] { w->hide(); });
    on(save, [&] {
        AppConfig n = c;
        n.localCopy = localCopy->value();
        n.defaultCipher = encryption_utils::fromDropdownIndex(cipher->value());
        n.showEncryptionInCredentials = showAlg->value();
        n.autoClipboardClear = autoClear->value();
        n.clipboardTimeoutSeconds = std::max(1, std::atoi(clearAfter->value()));
        n.defaultUIMode = mode->value() == 0 ? "gui" : mode->value() == 1 ? "tui" : "auto";
        const bool restart = n.localCopy != c.localCopy;
        ConfigManager::getInstance().updateConfig(n);
        if (!ConfigManager::getInstance().saveConfig()) {
            fl_alert("Couldn't write %s", ConfigManager::configFile().c_str());
            return;
        }
        w->hide();
        flash(restart ? "saved, restart to switch modes" : "settings saved");
        showDetail(current_);  // e.g. the encryption row
    });
    runModal(w);
    delete w;
    callbacks_.resize(mark);
}

void GuiUIManager::changeMasterPassword() {
    const size_t mark = callbacks_.size();
    const int W = 460, H = 440, x = 28, fw = W - 2 * x;
    auto* w = new Fl_Double_Window(W, H);
    w->copy_label("Change master password");
    w->color(enclosure());
    text(x, 22, fw, 30, "Change master password", kSansBold, 20, ink());
    text(x, 56, fw, 40, "Your entries stay as they are. Your other devices will ask for the new password after their next sync.",
         kSans, kSmall, muted());
    auto* current = field<Fl_Secret_Input>(x, 128, fw, 36, "Current master password");
    auto* next = field<Fl_Secret_Input>(x, 196, fw, 36, "New master password");
    auto* repeat = field<Fl_Secret_Input>(x, 264, fw, 36, "Repeat the new one");
    Fl_Box* error = text(x, 312, fw, 44, "", kSans, kSmall, danger());
    Fl_Button* cancel = button(W - x - 208, H - 58, 100, 38, "Cancel");
    Fl_Button* save = button(W - x - 100, H - 58, 100, 38, "Change", Kind::Primary);
    save->shortcut(FL_Enter);
    w->end();

    on(cancel, [w] { w->hide(); });
    on(save, [&, this] {
        std::string why;
        if (safeChangeMasterPassword(current->value(), next->value(), repeat->value(), why)) {
            w->hide();
            flash("master password changed");
        } else {
            error->copy_label(literal(why).c_str());
        }
    });
    current->take_focus();
    runModal(w);
    for (Fl_Secret_Input* f : {current, next, repeat}) f->value("");  // don't leave them in widget memory
    delete w;
    callbacks_.resize(mark);
}

void GuiUIManager::setPinDialog() {
    const size_t mark = callbacks_.size();
    const int W = 460, H = 470, x = 28, fw = W - 2 * x;
    auto* w = new Fl_Double_Window(W, H);
    w->copy_label("PIN unlock");
    w->color(enclosure());
    text(x, 22, fw, 30, "PIN unlock", kSansBold, 20, ink());
    text(x, 56, fw, 56,
         "Unlock this computer with a PIN. The ESP32 checks it and allows 5 wrong tries, then the master password is "
         "needed again. The PIN only works while the board is reachable.",
         kSans, kSmall, muted());
    auto* master = field<Fl_Secret_Input>(x, 144, fw, 36, "Master password");
    auto* pin = field<Fl_Secret_Input>(x, 212, fw, 36, "PIN (at least 4 digits)");
    auto* repeat = field<Fl_Secret_Input>(x, 280, fw, 36, "Repeat the PIN");
    Fl_Box* error = text(x, 328, fw, 44, "", kSans, kSmall, danger());
    Fl_Button* cancel = button(W - x - 208, H - 58, 100, 38, "Cancel");
    Fl_Button* save = button(W - x - 100, H - 58, 100, 38, "Set PIN", Kind::Primary);
    save->shortcut(FL_Enter);
    w->end();

    on(cancel, [w] { w->hide(); });
    on(save, [&, this] {
        error->labelcolor(muted());
        error->copy_label("Setting the PIN...");
        Fl::flush();  // a slow key derivation plus a round trip to the board
        error->labelcolor(danger());
        std::string why;
        if (safeSetPin(master->value(), pin->value(), repeat->value(), why)) {
            w->hide();
            flash("pin set");
        } else {
            error->copy_label(literal(why).c_str());
        }
    });
    master->take_focus();
    runModal(w);
    for (Fl_Secret_Input* f : {master, pin, repeat}) f->value("");
    delete w;
    callbacks_.resize(mark);
}

void GuiUIManager::runConnector() {
    std::string detail, address;
    if (checkBoard(detail, address) == BoardState::Connected) return;

    const size_t mark = callbacks_.size();
    const int W = 520, H = 300, x = 28, fw = W - 2 * x;
    auto* w = new Fl_Double_Window(W, H);
    w->copy_label("Pair with your host");
    w->color(enclosure());
    text(x, 22, fw, 30, "Pair with your host", kSansBold, 20, ink());
    Fl_Box* status = text(x, 58, fw, 64, "", kSans, kSmall, muted());
    text(x,
         128,
         fw,
         40,
         "To pair: open pairing on the host (BOOT on the board), then press Pair.",
         kSans,
         kSmall,
         muted());
    text(x, H - 118, fw, 40,
         ConfigManager::getInstance().getConfig().localCopy
             ? "Without it, the app uses this computer's copy and syncs with any other host."
             : "Device-only mode: without the host there's no vault to open.",
         kSans, kSmall, muted());
    Fl_Button* skip = button(x, H - 58, 190, 38, "Continue without it");
    Fl_Button* retry = button(W - x - 120 - 12 - 130, H - 58, 130, 38, "Check again");
    Fl_Button* pair = button(W - x - 120, H - 58, 120, 38, "Pair...", Kind::Primary);
    w->end();

    auto recheck = [&] {
        w->cursor(FL_CURSOR_WAIT);
        Fl::flush();
        const bool done = checkBoard(detail, address) == BoardState::Connected;
        w->cursor(FL_CURSOR_DEFAULT);
        if (done) return w->hide();
        status->copy_label(literal(detail).c_str());
        w->redraw();
    };
    on(retry, recheck);
    on(skip, [w] { w->hide(); });
    on(pair, [&] {
        if (!addHostDialog(address).empty()) recheck();  // closes the window once every host takes us
    });
    status->copy_label(literal(detail).c_str());
    pair->take_focus();
    runModal(w);
    delete w;
    callbacks_.resize(mark);
}

void GuiUIManager::openDevices() {
    const size_t mark = callbacks_.size();
    const int W = 560, H = 540, x = 28, fw = W - 2 * x;
    auto* w = new Fl_Double_Window(W, H);
    w->copy_label("Devices");
    w->color(enclosure());
    text(x, 22, fw, 30, "Hosts and devices", kSansBold, 20, ink());
    text(x, 56, fw, 44,
         "Hosts keep a copy of the vault for your devices: the ESP32 board, or a computer running pwvault --serve. "
         "This computer syncs with whichever it can reach.",
         kSans, kSmall, muted());
    Fl_Choice* pick = choice(x, 124, fw - 232, 36, "Host");
    Fl_Button* forget = button(x + fw - 220, 124, 100, 36, "Forget");
    Fl_Button* addHost = button(x + fw - 108, 124, 108, 36, "Add host");
    Fl_Box* hostState = text(x, 162, fw - 150, 24, "", kSans, kSmall, muted());
    Fl_Button* move = button(x + fw - 140, 162, 140, 26, "Change address");
    text(x, 190, fw, 22, "Devices paired with this host", kSansBold, kBody, ink());
    auto* list = new EntryList(x, 216, fw, 180);
    Fl_Box* status = text(x, 402, fw, 60, "", kSans, kSmall, muted());
    Fl_Button* revoke = button(x, H - 58, 120, 38, "Revoke", Kind::Danger);
    Fl_Button* add = button(W - x - 100 - 12 - 140, H - 58, 140, 38, "Add a device");
    Fl_Button* close = button(W - x - 100, H - 58, 100, 38, "Close", Kind::Primary);
    w->end();
    if (deviceOnly_) addHost->deactivate();

    std::vector<EspStore::Device> devices;
    auto say = [&](const std::string& msg, bool bad) {
        status->labelcolor(bad ? danger() : muted());
        status->copy_label(literal(msg).c_str());
    };
    auto host = [&]() -> const PairedHost* {
        return pick->value() >= 0 && pick->value() < static_cast<int>(hosts_.size()) ? &hosts_[pick->value()] : nullptr;
    };
    auto reload = [&] {
        list->clear();
        devices.clear();
        revoke->deactivate();
        const PairedHost* h = host();
        for (Fl_Widget* b :
             {static_cast<Fl_Widget*>(forget), static_cast<Fl_Widget*>(add), static_cast<Fl_Widget*>(move)})
            h ? b->activate() : b->deactivate();
        hostState->copy_label(h ? literal(std::string(hostRoleName(h->role)) + " host, " + hostStatusText(*h)).c_str()
                                : "No hosts yet: this computer keeps the vault on its own. Add one to sync.");
        if (!h) return say("", false), w->redraw();
        std::string error;
        EspStore::Storage storage;
        auto got = safeListDevices(*h->store, error, &storage);
        devices = got ? *got : std::vector<EspStore::Device>{};
        for (const auto& d : devices)
            list->add((d.name + (d.thisDevice ? "  (this computer)" : "") + "   " + lastSeenText(d.lastSeen)).c_str());
        got ? say(storageText(storage), false) : say(error, true);
        w->redraw();
    };
    auto fillHosts = [&](const std::string& select) {  // select: a host id; "" or unknown = the first
        pick->clear();
        int at = hosts_.empty() ? -1 : 0;
        for (size_t i = 0; i < hosts_.size(); i++) {
            pick->add(literal(hosts_[i].address).c_str());  // literal: no FLTK symbols
            if (hosts_[i].id == select) at = static_cast<int>(i);
        }
        pick->value(at);
        reload();
    };
    on(pick, reload);
    on(addHost, [&] {
        const std::string id = addHostDialog();
        if (!id.empty()) fillHosts(id);  // hosts are in role order, so the new one isn't necessarily last
    });
    on(move, [&] {
        const PairedHost* h = host();
        if (!h) return;
        const char* to = fl_input("It joined another network? Type the address it shows now.", h->address.c_str());
        std::string error;
        if (!to || !*to) return;
        const std::string id = h->id;
        if (!safeSetHostAddress(id, to, error)) return say(error, true);
        fillHosts(id);
    });
    on(forget, [&] {
        const PairedHost* h = host();
        if (!h) return;
        const std::string q = "Forget " + h->address + "? This computer stops syncing with it and deletes its "
                              "certificate for it. The vault on this computer stays.\n\nAsking the host to revoke "
                              "this computer first needs an approval there (BOOT on the board).";
        const int how = fl_choice("%s", "Cancel", "Forget", "Revoke, then forget", literal(q).c_str());
        if (how == 0) return;
        say(how == 2 ? "Approve the revoke on the host (BOOT on the board), within a minute..." : "", false);
        w->cursor(FL_CURSOR_WAIT);
        Fl::flush();
        std::string error;
        const bool ok = safeForgetHost(h->id, how == 2, error);
        w->cursor(FL_CURSOR_DEFAULT);
        fillHosts("");
        if (!ok) say(error, true);
    });
    on(list, [&] { list->value() ? revoke->activate() : revoke->deactivate(); });
    on(revoke, [&] {
        if (!list->value()) return;
        const EspStore::Device d = devices[list->value() - 1];
        const std::string q = "Revoke " + d.name + "? It loses access to the vault until it is paired again." +
                              (d.thisDevice ? "\n\nThat's this computer: you'll be locked out here." : "");
        if (fl_choice("%s", "Cancel", "Revoke", nullptr, literal(q).c_str()) != 1) return;
        say("Press BOOT on the board to confirm (within a minute)...", false);
        w->cursor(FL_CURSOR_WAIT);
        Fl::flush();  // the call below blocks until the press
        // ponytail: blocks the UI up to a minute; a worker thread if that ever matters
        std::string error;
        const bool ok = host() && safeRevokeDevice(*host()->store, d.name, error);
        w->cursor(FL_CURSOR_DEFAULT);
        reload();
        ok ? say("Revoked " + d.name + ".", false) : say(error, true);
    });
    on(add, [&] {
        std::string error;
        const auto invite = host() ? safeOpenPairing(*host()->store, error) : std::nullopt;
        if (!invite) return say(error, true);
        showPairingCode(*invite);
        reload();  // the new device, if it was approved
    });
    on(close, [w] { w->hide(); });
    fillHosts("");
    runModal(w);
    delete w;
    callbacks_.resize(mark);
}

std::string GuiUIManager::addHostDialog(const std::string& at) {
    const size_t mark = callbacks_.size();
    const int W = 520, H = 420, x = 28, fw = W - 2 * x;
    auto* w = new Fl_Double_Window(W, H);
    w->copy_label("Add a host");
    w->color(enclosure());
    text(x, 22, fw, 30, "Add a host", kSansBold, 20, ink());
    text(x, 56, fw, 66,
         "1. On the host, open pairing: press BOOT on the board. It shows a code for 2 minutes.\n"
         "2. Type its address and the code below, and press Pair.\n3. Approve this computer on the host (BOOT again).",
         kSans, kSmall, muted());
    auto* address = field<Fl_Input>(x, 150, fw, 36, "Host address (the IP it shows; add :port if it isn't the board)");
    address->value(at.c_str());
    auto* name = field<Fl_Input>(x, 214, 190, 36, "Name for this computer");
    name->value(defaultDeviceName().c_str());
    auto* code = field<Fl_Input>(x + 206, 214, fw - 206, 36, "Code on the host");
    Fl_Box* error = text(x, 262, fw, 80, "", kSans, kSmall, danger());
    Fl_Button* cancel = button(x, H - 58, 100, 38, "Cancel");
    Fl_Button* pair = button(W - x - 100, H - 58, 100, 38, "Pair", Kind::Primary);
    pair->shortcut(FL_Enter);
    w->end();
    std::string paired;  // its id
    on(cancel, [w] { w->hide(); });
    on(pair, [&] {
        const std::string c = normalizePairCode(code->value());
        if (!validDeviceName(name->value()))
            return error->copy_label("Use 1-20 characters of a-z, 0-9 and - for the name.");
        if (c.empty()) return error->copy_label("The code has 16 characters.");
        error->labelcolor(muted());
        error->copy_label(literal("Now approve '" + std::string(name->value()) + "' on the host (BOOT on the board), "
                                  "within a minute...").c_str());
        w->cursor(FL_CURSOR_WAIT);
        Fl::flush();
        // ponytail: blocks the window until the host answers (<= 90 s), like the connector
        std::string why;
        safeAddHost(address->value(), name->value(), c, why, &paired);
        w->cursor(FL_CURSOR_DEFAULT);
        error->labelcolor(danger());
        if (!paired.empty()) return w->hide();
        error->copy_label(literal(why).c_str());
    });
    (at.empty() ? static_cast<Fl_Widget*>(address) : code)->take_focus();
    runModal(w);
    delete w;
    callbacks_.resize(mark);
    return paired;
}

void GuiUIManager::showPairingCode(const EspStore::PairInvite& invite) {
    const size_t mark = callbacks_.size();
    const int W = 440, H = 600, x = 28, fw = W - 2 * x;
    auto* w = new Fl_Double_Window(W, H);
    w->copy_label("Add a device");
    w->color(enclosure());
    text(x, 22, fw, 30, "Add a device", kSansBold, 20, ink());
    text(x, 56, fw, 44, "Open pwvault on the phone and scan this code. Then press BOOT on the board to let it in.",
         kSans, kSmall, muted());
    auto* qr = new QrBox(x, 108, fw, fw);
    qr->setText(invite.qr);
    const std::string& c = invite.code;  // grouped like the OLED shows it
    text(x, 108 + fw + 12, fw, 24, "Code  " + c.substr(0, 4) + "-" + c.substr(4, 4) + "-" + c.substr(8, 4) + "-" +
         c.substr(12), kMono, kValue, ink());
    Fl_Box* left = text(x, 108 + fw + 40, fw, 24, "", kSans, kSmall, muted());
    Fl_Button* close = button(W - x - 100, H - 58, 100, 38, "Done", Kind::Primary);
    w->end();
    PairCountdown countdown{left, std::time(nullptr) + invite.seconds};
    tickPairCountdown(&countdown);
    on(close, [w] { w->hide(); });
    runModal(w);
    Fl::remove_timeout(tickPairCountdown, &countdown);
    delete w;
    callbacks_.resize(mark);
}

// ---- UIManager interface ----

bool GuiUIManager::addCredential(const std::string& platform,
                                 const std::string& username,
                                 const std::string& password,
                                 std::optional<CipherAlg> encryptionType) {
    if (!isLoggedIn || !safeAddCredential(platform, username, password, encryptionType)) return false;
    platforms_ = safeGetPlatforms();
    search_->value("");
    refreshList(platform);
    flash("saved " + platform);
    return true;
}

bool GuiUIManager::updateCredential(const std::string& platform,
                                    const std::string& username,
                                    const std::string& password,
                                    std::optional<CipherAlg> encryptionType) {
    if (!UIManager::updateCredential(platform, username, password, encryptionType)) return false;
    refreshList(platform);
    flash("saved " + platform);
    return true;
}

void GuiUIManager::viewCredential(const std::string& platform) {
    if (isLoggedIn) refreshList(platform);
}

bool GuiUIManager::deleteCredential(const std::string& platform) {
    if (!isLoggedIn) return false;
    fl_message_title("Delete entry");
    if (fl_choice("Delete %s? It's removed from all your devices.", "Cancel", "Delete", nullptr,
                  literal(platform).c_str()) != 1)
        return false;
    if (!safeDeleteCredential(platform)) {
        showMessage("Delete entry", "Couldn't delete " + platform + ".", true);
        return false;
    }
    current_.reset();
    selected_.clear();
    platforms_ = safeGetPlatforms();
    refreshList();
    flash("deleted " + platform);
    return true;
}

void GuiUIManager::showMessage(const std::string& title, const std::string& message, bool isError) {
    if (!isError && vaultWin_) return flash(message);
    fl_message_title(title.c_str());
    if (isError)
        fl_alert("%s", message.c_str());
    else
        fl_message("%s", message.c_str());
}
