#include "Theme.h"

#include <FL/Fl.H>
#include <FL/fl_draw.H>
#ifdef HAVE_FONTCONFIG
#include <fontconfig/fontconfig.h>
#endif

namespace theme {

Fl_Boxtype FLAT_BUTTON = FL_FREE_BOXTYPE, FLAT_BUTTON_DOWN = Fl_Boxtype(FL_FREE_BOXTYPE + 1),
           FLAT_FIELD = Fl_Boxtype(FL_FREE_BOXTYPE + 2);

namespace {
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

void apply() {
#ifdef HAVE_FONTCONFIG
    FcInit();  // FLTK 1.3's Xft code skips it, and fontconfig >= 2.17 warns
#endif
    Fl::scheme("none");
    Fl::background(0xE4, 0xE7, 0xE3);
    Fl::background2(0xF6, 0xF7, 0xF5);
    Fl::foreground(0x1A, 0x20, 0x1C);
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
            b->labelcolor(FL_WHITE);
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
