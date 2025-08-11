#include "UITheme.h"
#include <FL/Fl_Widget.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Input.H>
#include <FL/fl_draw.H>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <string>

bool UITheme::initialized = false;

void UITheme::initialize() {
    if (initialized) return;
    
    // Set the default color scheme
    Fl::set_color(FL_BACKGROUND_COLOR, Colors::BACKGROUND);
    Fl::set_color(FL_BACKGROUND2_COLOR, Colors::SURFACE);
    Fl::set_color(FL_FOREGROUND_COLOR, Colors::TEXT_PRIMARY);
    Fl::set_color(FL_SELECTION_COLOR, Colors::PRIMARY);
    
    // Set default fonts and sizes
    Fl::set_font(FL_HELVETICA, "Ubuntu");
    Fl::set_font(FL_HELVETICA_BOLD, "Ubuntu Bold");
    
    initialized = true;
}

void UITheme::styleButton(Fl_Widget* button, const std::string& variant) {
    if (!button) return;
    
    button->labelsize(Typography::BUTTON);
    button->labelfont(FL_HELVETICA_BOLD);
    
    if (variant == "primary") {
        button->color(Colors::PRIMARY);
        button->labelcolor(Colors::TEXT_PRIMARY);
        button->selection_color(Colors::PRIMARY_DARK);
    } else if (variant == "secondary") {
        button->color(Colors::SURFACE_VARIANT);
        button->labelcolor(Colors::TEXT_PRIMARY);
        button->selection_color(Colors::HOVER);
    } else if (variant == "outlined") {
        button->color(Colors::BACKGROUND);
        button->labelcolor(Colors::PRIMARY);
        button->selection_color(Colors::HOVER);
        button->box(FL_BORDER_BOX);
    }
    
    // Set minimum dimensions
    if (button->w() < Dimensions::BUTTON_MIN_WIDTH) {
        button->size(Dimensions::BUTTON_MIN_WIDTH, button->h());
    }
    if (button->h() < Dimensions::BUTTON_HEIGHT) {
        button->size(button->w(), Dimensions::BUTTON_HEIGHT);
    }
}

void UITheme::styleInput(Fl_Widget* input, bool hasError) {
    if (!input) return;
    
    input->labelsize(Typography::BODY_1);
    
    // Only set text properties if it's actually an input widget
    Fl_Input* inputWidget = dynamic_cast<Fl_Input*>(input);
    if (inputWidget) {
        inputWidget->textsize(Typography::BODY_1);
        inputWidget->textfont(FL_HELVETICA);
        
        if (hasError) {
            inputWidget->color(Colors::SURFACE);
            inputWidget->textcolor(Colors::TEXT_PRIMARY);
            inputWidget->selection_color(Colors::ERROR);
            inputWidget->box(FL_DOWN_BOX);
        } else {
            inputWidget->color(Colors::SURFACE);
            inputWidget->textcolor(Colors::TEXT_PRIMARY);
            inputWidget->selection_color(Colors::PRIMARY);
            inputWidget->box(FL_DOWN_BOX);
        }
    }
    
    // Set standard height
    if (input->h() < Dimensions::INPUT_HEIGHT) {
        input->size(input->w(), Dimensions::INPUT_HEIGHT);
    }
}

void UITheme::styleWindow(Fl_Window* window) {
    if (!window) return;
    
    window->color(Colors::BACKGROUND);
    window->labelcolor(Colors::TEXT_PRIMARY);
    window->labelfont(FL_HELVETICA_BOLD);
    window->labelsize(Typography::HEADLINE_2);
}

void UITheme::styleText(Fl_Widget* widget, const std::string& variant) {
    if (!widget) return;
    
    widget->labelcolor(Colors::TEXT_PRIMARY);
    widget->color(Colors::BACKGROUND);
    
    if (variant == "headline1") {
        widget->labelsize(Typography::HEADLINE_1);
        widget->labelfont(FL_HELVETICA_BOLD);
        widget->labelcolor(Colors::TEXT_PRIMARY);
    } else if (variant == "headline2") {
        widget->labelsize(Typography::HEADLINE_2);
        widget->labelfont(FL_HELVETICA_BOLD);
        widget->labelcolor(Colors::TEXT_PRIMARY);
    } else if (variant == "headline3") {
        widget->labelsize(Typography::HEADLINE_3);
        widget->labelfont(FL_HELVETICA_BOLD);
        widget->labelcolor(Colors::TEXT_PRIMARY);
    } else if (variant == "body1") {
        widget->labelsize(Typography::BODY_1);
        widget->labelfont(FL_HELVETICA);
        widget->labelcolor(Colors::TEXT_PRIMARY);
    } else if (variant == "body2") {
        widget->labelsize(Typography::BODY_2);
        widget->labelfont(FL_HELVETICA);
        widget->labelcolor(Colors::TEXT_SECONDARY);
    } else if (variant == "caption") {
        widget->labelsize(Typography::CAPTION);
        widget->labelfont(FL_HELVETICA);
        widget->labelcolor(Colors::TEXT_SECONDARY);
    }
}

void UITheme::drawCard(int x, int y, int w, int h, int elevation) {
    // Draw shadow based on elevation
    if (elevation > 0) {
        fl_color(fl_darker(Colors::BACKGROUND));
        for (int i = 0; i < elevation; i++) {
            fl_rectf(x + i, y + i, w, h);
        }
    }
    
    // Draw card background
    fl_color(Colors::SURFACE);
    fl_rectf(x, y, w, h);
    
    // Draw subtle border
    fl_color(Colors::BORDER);
    fl_rect(x, y, w, h);
}

void UITheme::drawRoundedRect(int x, int y, int w, int h, int radius, Fl_Color color) {
    fl_color(color);
    
    // For now, use regular rectangles since FLTK doesn't have native rounded rect support
    // In a real implementation, you'd use platform-specific drawing or a graphics library
    fl_rectf(x, y, w, h);
    
    // Draw border to simulate rounded appearance
    fl_color(fl_darker(color));
    fl_rect(x, y, w, h);
}

Fl_Color UITheme::getContrastTextColor(Fl_Color backgroundColor) {
    // Simple contrast calculation - in a real implementation you'd use proper luminance calculation
    unsigned char r, g, b;
    Fl::get_color(backgroundColor, r, g, b);
    
    int luminance = (r * 299 + g * 587 + b * 114) / 1000;
    return (luminance > 128) ? Colors::BACKGROUND : Colors::TEXT_PRIMARY;
}

Fl_Color UITheme::hexToFlColor(const std::string& hex) {
    if (hex.empty() || hex[0] != '#' || hex.length() != 7) {
        return FL_BLACK;
    }
    
    std::string hexValue = hex.substr(1);
    unsigned long color = std::stoul(hexValue, nullptr, 16);
    
    // Convert to FLTK color format (RRGGBB00)
    return static_cast<Fl_Color>((color << 8) | 0x00);
}

void UITheme::applyThemeToWindow(Fl_Window* window) {
    if (!window) return;
    
    initialize();
    styleWindow(window);
    
    // Recursively style all child widgets
    for (int i = 0; i < window->children(); i++) {
        Fl_Widget* child = window->child(i);
        
        // Apply appropriate styling based on widget type
        if (dynamic_cast<Fl_Button*>(child)) {
            UITheme::styleButton(child, "primary");
        } else if (dynamic_cast<Fl_Input*>(child)) {
            UITheme::styleInput(child, false);
        } else if (dynamic_cast<Fl_Window*>(child)) {
            applyThemeToWindow(dynamic_cast<Fl_Window*>(child));
        } else {
            UITheme::styleText(child, "body1");
        }
    }
}

void UITheme::drawModernButton(Fl_Widget* widget, int x, int y, int w, int h, const std::string& variant) {
    // Custom button drawing implementation
    Fl_Color buttonColor = (variant == "primary") ? Colors::PRIMARY : Colors::SURFACE_VARIANT;
    
    // Draw button background with slight rounding effect
    drawRoundedRect(x, y, w, h, BorderRadius::BUTTON, buttonColor);
    
    // Draw hover state if needed
    if (Fl::focus() == widget) {
        fl_color(Colors::FOCUS);
        fl_rect(x, y, w, h);
    }
}

void UITheme::drawModernInput(Fl_Widget* widget, int x, int y, int w, int h, bool hasError) {
    // Custom input drawing implementation
    Fl_Color inputColor = hasError ? fl_color_average(Colors::ERROR, Colors::SURFACE, 0.1f) : Colors::SURFACE;
    
    // Draw input background
    fl_color(inputColor);
    fl_rectf(x, y, w, h);
    
    // Draw border
    Fl_Color borderColor = hasError ? Colors::ERROR : 
                          (Fl::focus() == widget) ? Colors::BORDER_FOCUS : Colors::BORDER;
    fl_color(borderColor);
    fl_rect(x, y, w, h);
}
