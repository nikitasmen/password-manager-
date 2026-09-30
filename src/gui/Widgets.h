#ifndef GUI_WIDGETS_H
#define GUI_WIDGETS_H

#include <FL/Fl_Hold_Browser.H>
#include <FL/Fl_Widget.H>

#include <string>
#include <vector>

// The ESP32's screen, reproduced: black panel, lit dots, the board's own 5x7 font (oled_font.h).
// Coordinates are in OLED pixels; each is drawn as a `dot` x `dot` square (with a 1px gap at dot >= 3,
// like a real panel's pixel grid).
class OledPanel : public Fl_Widget {
   public:
    struct Text {
        std::string text;
        int x, y;      // OLED pixels
        int size = 1;  // 1 = 5x7 glyphs, 2 = 10x14 (the board's clock)
    };
    OledPanel(int x, int y, int w, int h, int dot);
    void setText(std::vector<Text> texts);
    [[nodiscard]] int columns() const { return w() / dot_; }  // width in OLED pixels

   protected:
    void draw() override;

   private:
    int dot_;
    std::vector<Text> texts_;
};

// A QR code, black modules on white with a 4-module quiet zone, scaled to the largest whole module size that fits.
// Always black on white, whatever the theme: that's what phone scanners read most reliably.
class QrBox : public Fl_Widget {
   public:
    QrBox(int x, int y, int w, int h) : Fl_Widget(x, y, w, h) {}
    void setText(const std::string& text);  // "" = nothing

   protected:
    void draw() override;

   private:
    std::vector<std::vector<bool>> modules_;
};

// The entry list: tall rows, the selected one tinted with an accent bar on its left edge.
class EntryList : public Fl_Hold_Browser {
   public:
    EntryList(int x, int y, int w, int h) : Fl_Hold_Browser(x, y, w, h) {}

   protected:
    int item_height(void* item) const override;
    void item_draw(void* item, int x, int y, int w, int h) const override;
};

#endif  // GUI_WIDGETS_H
