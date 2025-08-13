#ifndef MODERN_COMPONENTS_H
#define MODERN_COMPONENTS_H

#include "GuiComponent.h"
#include "UITheme.h"
#include <FL/Fl_Box.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Progress.H>
#include <FL/Fl_Scroll.H>
#include <FL/Fl_Group.H>
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <cctype>

/**
 * @class ModernCard
 * @brief A modern card container with elevation and rounded corners
 */
class ModernCard : public Fl_Group {
private:
    int elevation;
    std::string title;
    
public:
    ModernCard(int x, int y, int w, int h, const std::string& title = "", int elevation = 1)
        : Fl_Group(x, y, w, h), elevation(elevation), title(title) {
        box(FL_FLAT_BOX);
        color(UITheme::Colors::SURFACE);
    }
    
    void draw() override {
        // Draw card background with elevation
        UITheme::drawCard(x(), y(), w(), h(), elevation);
        
        // Draw title if provided
        if (!title.empty()) {
            fl_color(UITheme::Colors::TEXT_PRIMARY);
            fl_font(FL_HELVETICA_BOLD, UITheme::Typography::HEADLINE_3);
            fl_draw(title.c_str(), x() + UITheme::Spacing::MEDIUM, 
                   y() + UITheme::Spacing::MEDIUM + UITheme::Typography::HEADLINE_3);
        }
        
        // Draw children
        Fl_Group::draw();
    }
    
    void setElevation(int newElevation) { 
        elevation = newElevation; 
        redraw();
    }
    
    void setTitle(const std::string& newTitle) { 
        title = newTitle; 
        redraw();
    }
};

/**
 * @class ModernButton
 * @brief Enhanced button with hover effects, loading states, and modern styling
 */
class ModernButton : public Fl_Button {
private:
    std::string variant;
    bool isLoading;
    bool isHovered;
    std::function<void()> clickCallback;
    
public:
    ModernButton(int x, int y, int w, int h, const std::string& label, 
                const std::string& variant = "primary")
        : Fl_Button(x, y, w, h, label.c_str()), variant(variant), 
          isLoading(false), isHovered(false) {
        
        UITheme::styleButton(this, variant);
        
        // Set up hover tracking
        callback([](Fl_Widget* w, void* data) {
            ModernButton* btn = static_cast<ModernButton*>(w);
            if (btn->clickCallback && !btn->isLoading) {
                btn->clickCallback();
            }
        });
    }
    
    void draw() override {
        // Custom drawing for modern appearance
        Fl_Color bgColor;
        
        if (isLoading) {
            bgColor = UITheme::Colors::TEXT_DISABLED;
        } else if (variant == "primary") {
            bgColor = isHovered ? UITheme::Colors::PRIMARY_LIGHT : UITheme::Colors::PRIMARY;
        } else if (variant == "secondary") {
            bgColor = isHovered ? UITheme::Colors::HOVER : UITheme::Colors::SURFACE_VARIANT;
        } else { // outlined
            bgColor = isHovered ? UITheme::Colors::HOVER : UITheme::Colors::BACKGROUND;
        }
        
        // Draw button background
        fl_color(bgColor);
        fl_rectf(x(), y(), w(), h());
        
        // Draw border for outlined variant
        if (variant == "outlined") {
            fl_color(UITheme::Colors::PRIMARY);
            fl_rect(x(), y(), w(), h());
        }
        
        // Draw focus indicator
        if (Fl::focus() == this) {
            fl_color(UITheme::Colors::FOCUS);
            fl_line_style(FL_SOLID, 2);
            fl_rect(x() - 2, y() - 2, w() + 4, h() + 4);
            fl_line_style(FL_SOLID, 1);
        }
        
        // Draw label
        fl_color(labelcolor());
        fl_font(labelfont(), labelsize());
        
        if (isLoading) {
            fl_draw("Loading...", x(), y(), w(), h(), FL_ALIGN_CENTER);
        } else {
            fl_draw(label(), x(), y(), w(), h(), FL_ALIGN_CENTER);
        }
    }
    
    int handle(int event) override {
        switch (event) {
            case FL_ENTER:
                isHovered = true;
                redraw();
                return 1;
            case FL_LEAVE:
                isHovered = false;
                redraw();
                return 1;
            case FL_PUSH:
                take_focus();
                return 1;
            default:
                return Fl_Button::handle(event);
        }
    }
    
    void setLoading(bool loading) {
        isLoading = loading;
        redraw();
    }
    
    void setClickCallback(std::function<void()> callback) {
        clickCallback = callback;
    }
    
    void setVariant(const std::string& newVariant) {
        variant = newVariant;
        UITheme::styleButton(this, variant);
        redraw();
    }
};

/**
 * @class ModernInput
 * @brief Enhanced input field with validation, placeholders, and modern styling
 */
class ModernInput : public Fl_Input {
private:
    std::string placeholder;
    std::string errorMessage;
    bool hasError;
    bool isFocused;
    
public:
    ModernInput(int x, int y, int w, int h, const std::string& label = "")
        : Fl_Input(x, y, w, h, label.c_str()), hasError(false), isFocused(false) {
        
        UITheme::styleInput(this, false);
        
        // Set up focus tracking
        when(FL_WHEN_CHANGED | FL_WHEN_ENTER_KEY | FL_WHEN_NOT_CHANGED);
    }
    
    void draw() override {
        // Custom drawing for modern appearance
        UITheme::drawModernInput(this, x(), y(), w(), h(), hasError);
        
        // Draw the text content
        Fl_Input::draw();
        
        // Draw placeholder if empty and not focused
        if (size() == 0 && !isFocused && !placeholder.empty()) {
            fl_color(UITheme::Colors::TEXT_DISABLED);
            fl_font(textfont(), textsize());
            fl_draw(placeholder.c_str(), x() + UITheme::Spacing::SMALL, 
                   y() + UITheme::Spacing::SMALL, w() - UITheme::Spacing::MEDIUM, 
                   h() - UITheme::Spacing::MEDIUM, FL_ALIGN_LEFT);
        }
        
        // Draw error message below input
        if (hasError && !errorMessage.empty()) {
            fl_color(UITheme::Colors::ERROR);
            fl_font(FL_HELVETICA, UITheme::Typography::CAPTION);
            fl_draw(errorMessage.c_str(), x(), y() + h() + UITheme::Spacing::TINY, 
                   w(), UITheme::Typography::CAPTION + UITheme::Spacing::TINY, 
                   FL_ALIGN_LEFT);
        }
    }
    
    int handle(int event) override {
        switch (event) {
            case FL_FOCUS:
                isFocused = true;
                if (hasError) {
                    clearError();
                }
                redraw();
                return Fl_Input::handle(event);
            case FL_UNFOCUS:
                isFocused = false;
                redraw();
                return Fl_Input::handle(event);
            default:
                return Fl_Input::handle(event);
        }
    }
    
    void setPlaceholder(const std::string& text) {
        placeholder = text;
        redraw();
    }
    
    void setError(const std::string& message) {
        hasError = true;
        errorMessage = message;
        UITheme::styleInput(this, true);
        redraw();
    }
    
    void clearError() {
        hasError = false;
        errorMessage.clear();
        UITheme::styleInput(this, false);
        redraw();
    }
    
    bool getHasError() const { return hasError; }
    
    // Calculate total height including error message space
    int totalHeight() const {
        return h() + (hasError ? UITheme::Typography::CAPTION + UITheme::Spacing::MEDIUM : 0);
    }
};

/**
 * @class ModernSecretInput
 * @brief Enhanced secret input field with show/hide toggle and modern styling
 */
class ModernSecretInput : public Fl_Secret_Input {
private:
    std::string placeholder;
    std::string errorMessage;
    bool hasError;
    bool isFocused;
    bool showPassword;
    ModernButton* toggleButton;
    
public:
    ModernSecretInput(int x, int y, int w, int h, const std::string& label = "")
        : Fl_Secret_Input(x, y, w, h, label.c_str()), hasError(false), 
          isFocused(false), showPassword(false), toggleButton(nullptr) {
        
        UITheme::styleInput(this, false);
        
        // Create show/hide toggle button
        toggleButton = new ModernButton(x + w - 30, y + 5, 25, h - 10, "👁", "outlined");
        toggleButton->setClickCallback([this]() {
            togglePasswordVisibility();
        });
        
        when(FL_WHEN_CHANGED | FL_WHEN_ENTER_KEY | FL_WHEN_NOT_CHANGED);
    }
    
    ~ModernSecretInput() {
        delete toggleButton;
    }
    
    void draw() override {
        // Custom drawing for modern appearance
        UITheme::drawModernInput(this, x(), y(), w(), h(), hasError);
        
        // Draw the text content
        if (showPassword) {
            // Temporarily convert to regular input for display
            type(FL_NORMAL_INPUT);
            Fl_Input::draw();
            type(FL_SECRET_INPUT);
        } else {
            Fl_Secret_Input::draw();
        }
        
        // Draw placeholder if empty and not focused
        if (size() == 0 && !isFocused && !placeholder.empty()) {
            fl_color(UITheme::Colors::TEXT_DISABLED);
            fl_font(textfont(), textsize());
            fl_draw(placeholder.c_str(), x() + UITheme::Spacing::SMALL, 
                   y() + UITheme::Spacing::SMALL, w() - 40, 
                   h() - UITheme::Spacing::MEDIUM, FL_ALIGN_LEFT);
        }
        
        // Draw toggle button
        if (toggleButton) {
            toggleButton->draw();
        }
        
        // Draw error message below input
        if (hasError && !errorMessage.empty()) {
            fl_color(UITheme::Colors::ERROR);
            fl_font(FL_HELVETICA, UITheme::Typography::CAPTION);
            fl_draw(errorMessage.c_str(), x(), y() + h() + UITheme::Spacing::TINY, 
                   w(), UITheme::Typography::CAPTION + UITheme::Spacing::TINY, 
                   FL_ALIGN_LEFT);
        }
    }
    
    int handle(int event) override {
        // Let toggle button handle its events first
        if (toggleButton && toggleButton->handle(event)) {
            return 1;
        }
        
        switch (event) {
            case FL_FOCUS:
                isFocused = true;
                if (hasError) {
                    clearError();
                }
                redraw();
                return Fl_Secret_Input::handle(event);
            case FL_UNFOCUS:
                isFocused = false;
                redraw();
                return Fl_Secret_Input::handle(event);
            default:
                return Fl_Secret_Input::handle(event);
        }
    }
    
    void resize(int x, int y, int w, int h) override {
        Fl_Secret_Input::resize(x, y, w, h);
        if (toggleButton) {
            toggleButton->resize(x + w - 30, y + 5, 25, h - 10);
        }
    }
    
    void setPlaceholder(const std::string& text) {
        placeholder = text;
        redraw();
    }
    
    void setError(const std::string& message) {
        hasError = true;
        errorMessage = message;
        UITheme::styleInput(this, true);
        redraw();
    }
    
    void clearError() {
        hasError = false;
        errorMessage.clear();
        UITheme::styleInput(this, false);
        redraw();
    }
    
    bool getHasError() const { return hasError; }
    
    void togglePasswordVisibility() {
        showPassword = !showPassword;
        toggleButton->copy_label(showPassword ? "🙈" : "👁");
        redraw();
    }
    
    // Calculate total height including error message space
    int totalHeight() const {
        return h() + (hasError ? UITheme::Typography::CAPTION + UITheme::Spacing::MEDIUM : 0);
    }
};

/**
 * @class ModernProgressBar
 * @brief Modern progress bar with smooth animations and status text
 */
class ModernProgressBar : public Fl_Progress {
private:
    std::string statusText;
    bool isIndeterminate;
    
public:
    ModernProgressBar(int x, int y, int w, int h)
        : Fl_Progress(x, y, w, h), isIndeterminate(false) {
        
        selection_color(UITheme::Colors::PRIMARY);
        color(UITheme::Colors::SURFACE_VARIANT);
        minimum(0.0);
        maximum(100.0);
        value(0.0);
    }
    
    void draw() override {
        // Draw background
        fl_color(color());
        fl_rectf(x(), y(), w(), h());
        
        // Draw progress
        if (isIndeterminate) {
            // Animated indeterminate progress (simplified)
            fl_color(selection_color());
            int progressWidth = w() / 4;
            int offset = (int)(value()) % (w() + progressWidth);
            fl_rectf(x() + offset - progressWidth, y(), progressWidth, h());
        } else {
            // Regular progress bar
            int progressWidth = (int)((value() / maximum()) * w());
            fl_color(selection_color());
            fl_rectf(x(), y(), progressWidth, h());
        }
        
        // Draw border
        fl_color(UITheme::Colors::BORDER);
        fl_rect(x(), y(), w(), h());
        
        // Draw status text
        if (!statusText.empty()) {
            fl_color(UITheme::Colors::TEXT_PRIMARY);
            fl_font(FL_HELVETICA, UITheme::Typography::CAPTION);
            fl_draw(statusText.c_str(), x(), y() + h() + UITheme::Spacing::TINY, 
                   w(), UITheme::Typography::CAPTION, FL_ALIGN_CENTER);
        }
    }
    
    void setStatusText(const std::string& text) {
        statusText = text;
        redraw();
    }
    
    void setIndeterminate(bool indeterminate) {
        isIndeterminate = indeterminate;
        redraw();
    }
    
    void updateProgress(double percent, const std::string& status = "") {
        value(percent);
        if (!status.empty()) {
            setStatusText(status);
        }
        redraw();
    }
};

#endif // MODERN_COMPONENTS_H
