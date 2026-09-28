#ifndef GUI_THEME_H
#define GUI_THEME_H

// Visual language: the ESP32 box on the desk. Quiet cool-grey panes, one accent (solder-mask green),
// and the board's own OLED as the only bold element (see OledPanel in Widgets.h).

#include <FL/Enumerations.H>
#include <FL/Fl_Button.H>

namespace theme {

// Palette
inline Fl_Color enclosure() { return fl_rgb_color(0xE4, 0xE7, 0xE3); }  // window background
inline Fl_Color surface() { return fl_rgb_color(0xF6, 0xF7, 0xF5); }    // panes, inputs
inline Fl_Color line() { return fl_rgb_color(0xC9, 0xCE, 0xC9); }       // 1px dividers and borders
inline Fl_Color ink() { return fl_rgb_color(0x1A, 0x20, 0x1C); }        // text
inline Fl_Color muted() { return fl_rgb_color(0x68, 0x71, 0x6B); }      // labels, hints
inline Fl_Color accent() { return fl_rgb_color(0x1E, 0x6A, 0x45); }     // selection, primary action
inline Fl_Color accentTint() { return fl_rgb_color(0xDD, 0xEA, 0xE2); } // selected row
inline Fl_Color danger() { return fl_rgb_color(0xA5, 0x39, 0x2A); }     // delete, errors
inline Fl_Color oledOff() { return FL_BLACK; }
inline Fl_Color oledOn() { return fl_rgb_color(0xE6, 0xEE, 0xF3); }

// Type (FL_HELVETICA/_BOLD are remapped to FreeSans, FL_COURIER to JetBrains Mono, in apply())
constexpr Fl_Font kSans = FL_HELVETICA, kSansBold = FL_HELVETICA_BOLD, kMono = FL_COURIER;
constexpr int kSmall = 12, kBody = 14, kValue = 15, kTitle = 22;

// Box types: flat, 1px border. Buttons are filled with their color(); the down variant darkens it.
extern Fl_Boxtype FLAT_BUTTON, FLAT_BUTTON_DOWN, FLAT_FIELD;

void apply();  // once, before creating any window

// Buttons in the house style. Primary = accent fill; danger = red text; plain = surface with border;
// OnOled = for the black status strip: black fill, dim border, lit-pixel text.
enum class Kind { Plain, Primary, Danger, OnOled };
Fl_Button* button(int x, int y, int w, int h, const char* label, Kind kind = Kind::Plain);

}  // namespace theme

#endif  // GUI_THEME_H
