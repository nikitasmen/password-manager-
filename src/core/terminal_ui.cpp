#include "terminal_ui.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>

#include "oled_font.h"
#include "qrcodegen.hpp"

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#define isatty _isatty
#define STDOUT_FILENO 1
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace term {

namespace {
std::string paint(const std::string& s, const char* sgr) {
    return colors() ? std::string("\033[") + sgr + "m" + s + "\033[0m" : s;
}
}  // namespace

bool colors() {
    static const bool on = [] {
        if (const char* f = std::getenv("CLICOLOR_FORCE"); f && *f && std::string(f) != "0") return true;
        return isatty(STDOUT_FILENO) && !std::getenv("NO_COLOR");
    }();
    return on;
}

std::string accent(const std::string& s) {
    return paint(s, "38;2;63;163;116");
}
std::string muted(const std::string& s) {
    return paint(s, "38;2;138;147;141");
}
std::string danger(const std::string& s) {
    return paint(s, "38;2;208;96;78");
}
std::string bold(const std::string& s) {
    return paint(s, "1");
}

size_t visibleWidth(const std::string& s) {
    size_t n = 0;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '\033') {  // skip "\033[...m"
            while (i < s.size() && s[i] != 'm') i++;
            continue;
        }
        if ((static_cast<unsigned char>(s[i]) & 0xC0) != 0x80) n++;  // count UTF-8 lead bytes only
    }
    return n;
}

int width() {
#ifndef _WIN32
    winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
#endif
    return 80;
}

void clear() {
    if (isatty(STDOUT_FILENO)) std::cout << "\033[H\033[2J";
    std::cout << std::flush;
}

std::vector<std::string> oled(const std::string& text) {
    // pixel grid: 1px margin, 5x7 glyphs 6px apart (like Adafruit_GFX); 8 rows = 4 terminal lines
    const int w = static_cast<int>(text.size()) * 6 + 1, h = 8;
    std::vector<std::vector<bool>> px(h, std::vector<bool>(w + 1, false));
    for (size_t i = 0; i < text.size(); i++) {
        unsigned char ch = static_cast<unsigned char>(text[i]);
        if (ch < 0x20 || ch > 0x7E) ch = '?';
        for (int c = 0; c < 5; c++)
            for (int r = 0; r < 7; r++)
                if (kOledFont[ch - 0x20][c] >> r & 1) px[1 + r][1 + static_cast<int>(i) * 6 + c] = true;
    }
    std::vector<std::string> lines;
    for (int y = 0; y < h; y += 2) {
        std::string row;
        for (int x = 0; x <= w; x++) {
            bool top = px[y][x], bottom = px[y + 1][x];
            row += top && bottom ? "█" : top ? "▀" : bottom ? "▄" : " ";
        }
        lines.push_back(colors() ? "\033[48;2;0;0;0;38;2;230;238;243m" + row + "\033[0m" : row);
    }
    return lines;
}

std::string readLine(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string in;
    if (!std::getline(std::cin, in)) {  // Ctrl+D / closed input: leave cleanly
        std::cout << "\n";
        std::exit(0);
    }
    return in;
}

std::string readSecret(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string in;
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
    bool ok = static_cast<bool>(std::getline(std::cin, in));
    SetConsoleMode(h, mode);
#else
    termios old{};
    const bool tty = tcgetattr(STDIN_FILENO, &old) == 0;
    if (tty) {
        termios quiet = old;
        quiet.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
    }
    bool ok = static_cast<bool>(std::getline(std::cin, in));
    if (tty) tcsetattr(STDIN_FILENO, TCSANOW, &old);
#endif
    std::cout << "\n";
    if (!ok) std::exit(0);
    return in;
}

bool confirm(const std::string& question) {
    std::string a = readLine(question + " " + muted("[y/N]") + " ");
    return a == "y" || a == "Y" || a == "yes";
}

// Two modules per character row; colours set explicitly so it scans on dark terminal themes too.
std::string qrText(const std::string& text) {
    const auto qr = qrcodegen::QrCode::encodeText(text.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
    const int n = qr.getSize();
    auto dark = [&](int x, int y) { return x >= 0 && y >= 0 && x < n && y < n && qr.getModule(x, y); };
    std::string out;
    for (int y = -4; y < n + 4; y += 2) {
        out += "\033[30;47m";
        for (int x = -4; x < n + 4; x++) {
            const bool top = dark(x, y), bottom = dark(x, y + 1);
            out += top && bottom ? "\u2588" : top ? "\u2580" : bottom ? "\u2584" : " ";
        }
        out += "\033[0m\n";
    }
    return out;
}

}  // namespace term
