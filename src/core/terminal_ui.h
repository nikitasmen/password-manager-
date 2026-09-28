#ifndef TERMINAL_UI_H
#define TERMINAL_UI_H

// Terminal toolkit for the TUI: styles, the board's OLED drawn in half blocks, line input.
// Colors only when stdout is a terminal and NO_COLOR is unset (CLICOLOR_FORCE=1 forces them).

#include <string>
#include <vector>

namespace term {

bool colors();
std::string accent(const std::string& s);  // solder-mask green, lightened for dark and light terminals
std::string muted(const std::string& s);
std::string danger(const std::string& s);
std::string bold(const std::string& s);
size_t visibleWidth(const std::string& s);  // ignores color codes; counts UTF-8 code points
int width();                                // terminal columns (80 if unknown)

void clear();

// The ESP32's screen: `text` in its 5x7 font, lit pixels on black, 2 pixel rows per terminal line.
// Returns one string per terminal line (4 lines for one line of text).
std::vector<std::string> oled(const std::string& text);

std::string readLine(const std::string& prompt);
std::string readSecret(const std::string& prompt);  // no echo
bool confirm(const std::string& question);          // y/N, default no

}  // namespace term

#endif  // TERMINAL_UI_H
