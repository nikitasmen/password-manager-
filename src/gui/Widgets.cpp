#include "Widgets.h"

#include <FL/fl_draw.H>

#include <algorithm>

#include "Theme.h"
#include "../core/oled_font.h"
#include "../core/qrcodegen.hpp"

OledPanel::OledPanel(int x, int y, int w, int h, int dot) : Fl_Widget(x, y, w, h), dot_(dot) {
    box(FL_FLAT_BOX);
    color(theme::oledOff());
}

void OledPanel::setText(std::vector<Text> texts) {
    texts_ = std::move(texts);
    redraw();
}

void OledPanel::draw() {
    fl_color(theme::oledOff());
    fl_rectf(x(), y(), w(), h());
    fl_color(theme::oledOn());
    const int gap = dot_ >= 3 ? 1 : 0;
    for (const Text& t : texts_) {
        int col = t.x;
        for (unsigned char ch : t.text) {
            if (ch < 0x20 || ch > 0x7E) ch = '?';
            for (int c = 0; c < 5; c++) {
                unsigned char bits = kOledFont[ch - 0x20][c];
                for (int r = 0; r < 7; r++) {
                    if (!(bits >> r & 1)) continue;
                    int px = x() + (col + c * t.size) * dot_, py = y() + (t.y + r * t.size) * dot_;
                    int side = t.size * dot_;
                    if (px + side > x() + w() || py + side > y() + h()) continue;  // clip like the panel edge
                    // each OLED pixel of a size-s glyph is s x s dots
                    for (int sy = 0; sy < t.size; sy++)
                        for (int sx = 0; sx < t.size; sx++)
                            fl_rectf(px + sx * dot_, py + sy * dot_, dot_ - gap, dot_ - gap);
                }
            }
            col += 6 * t.size;  // 5 columns + 1 space, like Adafruit_GFX
        }
    }
}

int EntryList::item_height(void*) const {
    return 34;
}

void EntryList::item_draw(void* item, int x, int y, int w, int h) const {
    const bool selected = item_selected(item);
    fl_color(selected ? theme::accentTint() : theme::surface());
    fl_rectf(x, y, w, h);
    if (selected) {
        fl_color(theme::accent());
        fl_rectf(x, y, 3, h);
    }
    fl_font(selected ? theme::kSansBold : theme::kSans, theme::kValue);
    fl_color(theme::ink());
    fl_draw(item_text(item), x + 16, y, w - 20, h, FL_ALIGN_LEFT | FL_ALIGN_CLIP);
}

void QrBox::setText(const std::string& text) {
    modules_.clear();
    if (!text.empty()) {
        const auto qr = qrcodegen::QrCode::encodeText(text.c_str(), qrcodegen::QrCode::Ecc::MEDIUM);
        modules_.assign(qr.getSize(), std::vector<bool>(qr.getSize()));
        for (int y = 0; y < qr.getSize(); y++)
            for (int x = 0; x < qr.getSize(); x++) modules_[y][x] = qr.getModule(x, y);
    }
    redraw();
}

void QrBox::draw() {
    if (modules_.empty()) return;
    const int n = static_cast<int>(modules_.size()), total = n + 8;  // + quiet zone
    const int m = std::min(w(), h()) / total, side = m * total;
    const int x0 = x() + (w() - side) / 2, y0 = y() + (h() - side) / 2;
    fl_rectf(x0, y0, side, side, FL_WHITE);
    fl_color(FL_BLACK);
    for (int r = 0; r < n; r++)
        for (int c = 0; c < n; c++)
            if (modules_[r][c]) fl_rectf(x0 + (c + 4) * m, y0 + (r + 4) * m, m, m);
}
