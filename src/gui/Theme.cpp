#include "Theme.h"

#include <FL/Fl.H>
#include <FL/fl_draw.H>

#include <array>
#include <cstdio>
#include <cstdlib>
#ifdef HAVE_FONTCONFIG
#include <fontconfig/fontconfig.h>
#endif

namespace theme {

Fl_Boxtype FLAT_BUTTON = FL_FREE_BOXTYPE, FLAT_BUTTON_DOWN = Fl_Boxtype(FL_FREE_BOXTYPE + 1),
           FLAT_FIELD = Fl_Boxtype(FL_FREE_BOXTYPE + 2);

namespace {
const Palette kLight{fl_rgb_color(0xE4, 0xE7, 0xE3),
                     fl_rgb_color(0xF6, 0xF7, 0xF5),
                     FL_WHITE,
                     fl_rgb_color(0xC9, 0xCE, 0xC9),
                     fl_rgb_color(0x1A, 0x20, 0x1C),
                     fl_rgb_color(0x68, 0x71, 0x6B),
                     fl_rgb_color(0x1E, 0x6A, 0x45),
                     FL_WHITE,
                     fl_rgb_color(0xDD, 0xEA, 0xE2),
                     fl_rgb_color(0xA5, 0x39, 0x2A)};
// The same hues on graphite, as on Android (Ui.kt); the green is lifted to keep its contrast on the dark panes
const Palette kDark{fl_rgb_color(0x16, 0x1A, 0x18),
                    fl_rgb_color(0x1F, 0x24, 0x21),
                    fl_rgb_color(0x27, 0x2D, 0x29),
                    fl_rgb_color(0x34, 0x3B, 0x37),
                    fl_rgb_color(0xE3, 0xE8, 0xE4),
                    fl_rgb_color(0x9A, 0xA3, 0x9D),
                    fl_rgb_color(0x6C, 0xC1, 0x96),
                    fl_rgb_color(0x0E, 0x1F, 0x16),
                    fl_rgb_color(0x24, 0x3A, 0x2E),
                    fl_rgb_color(0xE3, 0x8A, 0x79)};
const Palette* current = &kLight;

// First line of a command's output, "" if it can't run
std::string firstLine(const char* cmd) {
    FILE* p = popen(cmd, "r");
    if (!p)
        return "";
    std::array<char, 128> buf{};
    std::string out = fgets(buf.data(), buf.size(), p) ? buf.data() : "";
    pclose(p);
    return out;
}

void setBackground(void (*set)(uchar, uchar, uchar), Fl_Color c) {
    uchar r, g, b;
    Fl::get_color(c, r, g, b);
    set(r, g, b);
}

void drawButton(int x, int y, int w, int h, Fl_Color c) {
    fl_color(c);
    fl_rectf(x, y, w, h);
    fl_color(c == accent() ? accent() : c == oledOff() ? fl_rgb_color(0x55, 0x5E, 0x63) : line());
    fl_rect(x, y, w, h);
}
void drawButtonDown(int x, int y, int w, int h, Fl_Color c) {
    drawButton(x, y, w, h, fl_color_average(c, FL_BLACK, 0.88f));
}
void drawField(int x, int y, int w, int h, Fl_Color c) {
    fl_color(c);
    fl_rectf(x, y, w, h);
    fl_color(line());
    fl_rect(x, y, w, h);
}
}  // namespace

const Palette& palette() {
    return *current;
}

bool wantsDark(const std::string& setting) {
    if (setting == "dark")
        return true;
    if (setting == "light")
        return false;
    // ponytail: GNOME/GTK (KDE mirrors its scheme there) and macOS; Windows stays light unless set to dark
    if (const char* gtk = std::getenv("GTK_THEME"); gtk && std::string(gtk).find(":dark") != std::string::npos)
        return true;
#ifdef __APPLE__
    return firstLine("defaults read -g AppleInterfaceStyle 2>/dev/null").rfind("Dark", 0) == 0;
#elif defined(_WIN32)
    return false;
#else
    return firstLine("gsettings get org.gnome.desktop.interface color-scheme 2>/dev/null").find("dark") !=
           std::string::npos;
#endif
}

void apply(bool dark) {
    current = dark ? &kDark : &kLight;
#ifdef HAVE_FONTCONFIG
    FcInit();  // FLTK 1.3's Xft code skips it, and fontconfig >= 2.17 warns
#endif
    Fl::scheme("none");
    setBackground(Fl::background, enclosure());
    setBackground(Fl::background2, field());
    setBackground(Fl::foreground, ink());
    Fl::set_color(FL_SELECTION_COLOR, accent());
    Fl::set_font(FL_HELVETICA, " FreeSans");
    Fl::set_font(FL_HELVETICA_BOLD, "BFreeSans");
    Fl::set_font(FL_COURIER, " JetBrainsMono Nerd Font Mono");
    FL_NORMAL_SIZE = kBody;

    Fl::set_boxtype(FLAT_BUTTON, drawButton, 1, 1, 2, 2);
    Fl::set_boxtype(FLAT_BUTTON_DOWN, drawButtonDown, 1, 1, 2, 2);
    Fl::set_boxtype(FLAT_FIELD, drawField, 2, 2, 4, 4);
    // Restyle FLTK's stock boxes too, so fl_message/fl_choice and the update dialog match
    Fl::set_boxtype(FL_UP_BOX, drawButton, 1, 1, 2, 2);
    Fl::set_boxtype(FL_DOWN_BOX, drawField, 2, 2, 4, 4);
    Fl::set_boxtype(FL_THIN_UP_BOX, drawButton, 1, 1, 2, 2);
    Fl::set_boxtype(FL_THIN_DOWN_BOX, drawField, 1, 1, 2, 2);
}

Fl_Button* button(int x, int y, int w, int h, const char* label, Kind kind) {
    auto* b = new Fl_Button(x, y, w, h, label);
    b->box(FLAT_BUTTON);
    b->down_box(FLAT_BUTTON_DOWN);
    b->labelfont(kSans);
    b->labelsize(kBody);
    switch (kind) {
        case Kind::Primary:
            b->color(accent());
            b->labelcolor(onAccent());
            b->labelfont(kSansBold);
            break;
        case Kind::Danger:
            b->color(surface());
            b->labelcolor(danger());
            break;
        case Kind::OnOled:  // draws its own black background: never relies on the strip behind it
            b->color(oledOff());
            b->labelcolor(oledOn());
            break;
        case Kind::Plain:
            b->color(surface());
            b->labelcolor(ink());
            break;
    }
    return b;
}

}  // namespace theme
