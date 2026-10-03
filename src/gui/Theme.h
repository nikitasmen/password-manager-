#ifndef GUI_THEME_H
#define GUI_THEME_H

// Visual language: the ESP32 box on the desk. Quiet cool-grey panes, one accent (solder-mask green),
// and the board's own OLED as the only bold element (see OledPanel in Widgets.h).

#include <FL/Enumerations.H>
#include <FL/Fl_Button.H>

#include <string>

namespace theme {

// Palette: light (the default) or dark, chosen by apply(). The OLED is black glass in both.
struct Palette {
    Fl_Color enclosure;   // window background
    Fl_Color surface;     // panes
    Fl_Color field;       // inputs, a step off the panes
    Fl_Color line;        // 1px dividers and borders
    Fl_Color ink;         // text
    Fl_Color muted;       // labels, hints
    Fl_Color accent;      // selection, primary action
    Fl_Color onAccent;    // text on the accent
    Fl_Color accentTint;  // selected row
    Fl_Color danger;      // delete, errors
};
const Palette& palette();
inline Fl_Color enclosure() { return palette().enclosure; }
inline Fl_Color surface() { return palette().surface; }
inline Fl_Color field() { return palette().field; }
inline Fl_Color line() { return palette().line; }
inline Fl_Color ink() { return palette().ink; }
inline Fl_Color muted() { return palette().muted; }
inline Fl_Color accent() { return palette().accent; }
inline Fl_Color onAccent() { return palette().onAccent; }
inline Fl_Color accentTint() { return palette().accentTint; }
inline Fl_Color danger() { return palette().danger; }
inline Fl_Color oledOff() { return FL_BLACK; }
inline Fl_Color oledOn() { return fl_rgb_color(0xE6, 0xEE, 0xF3); }

// Type (FL_HELVETICA/_BOLD are remapped to FreeSans, FL_COURIER to JetBrains Mono, in apply())
constexpr Fl_Font kSans = FL_HELVETICA, kSansBold = FL_HELVETICA_BOLD, kMono = FL_COURIER;
constexpr int kSmall = 12, kBody = 14, kValue = 15, kTitle = 22;

// Box types: flat, 1px border. Buttons are filled with their color(); the down variant darkens it.
extern Fl_Boxtype FLAT_BUTTON, FLAT_BUTTON_DOWN, FLAT_FIELD;

// The config's theme ("system", "light" or "dark") made concrete; "system" asks the desktop
bool wantsDark(const std::string& setting);
// Before creating any window; again to switch, then rebuild the windows (widgets keep the colors they were made with)
void apply(bool dark);

// Buttons in the house style. Primary = accent fill; danger = red text; plain = surface with border;
// OnOled = for the black status strip: black fill, dim border, lit-pixel text.
enum class Kind { Plain, Primary, Danger, OnOled };
Fl_Button* button(int x, int y, int w, int h, const char* label, Kind kind = Kind::Plain);

}  // namespace theme

#endif  // GUI_THEME_H
