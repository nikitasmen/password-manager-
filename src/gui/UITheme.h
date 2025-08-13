#ifndef UI_THEME_H
#define UI_THEME_H

#include <FL/Fl.H>
#include <FL/fl_draw.H>
#include <string>
#include <functional>
#include <utility>
#include <string>

/**
 * @class UITheme
 * @brief Modern UI theme system for the password manager
 * 
 * Provides a consistent, modern color scheme and styling system
 * for all GUI components following Material Design principles.
 */
class UITheme {
public:
    // Modern Color Palette - Dark theme with blue accent
    struct Colors {
        // Primary colors
        static constexpr Fl_Color PRIMARY = 0x1976D200;        // Material Blue 700
        static constexpr Fl_Color PRIMARY_LIGHT = 0x42A5F500;  // Material Blue 400
        static constexpr Fl_Color PRIMARY_DARK = 0x0D47A100;   // Material Blue 900
        
        // Surface colors (dark theme)
        static constexpr Fl_Color SURFACE = 0x1E1E1E00;        // Dark gray
        static constexpr Fl_Color SURFACE_VARIANT = 0x2C2C2C00; // Lighter dark gray
        static constexpr Fl_Color BACKGROUND = 0x12121200;      // Very dark gray
        
        // Text colors
        static constexpr Fl_Color TEXT_PRIMARY = 0xFFFFFF00;    // White
        static constexpr Fl_Color TEXT_SECONDARY = 0xB0B0B000;  // Light gray
        static constexpr Fl_Color TEXT_DISABLED = 0x70707000;   // Darker gray
        
        // Status colors
        static constexpr Fl_Color SUCCESS = 0x4CAF5000;         // Material Green 500
        static constexpr Fl_Color WARNING = 0xFF9800FF;         // Material Orange 500
        static constexpr Fl_Color ERROR = 0xF4433600;           // Material Red 500
        
        // Interactive states
        static constexpr Fl_Color HOVER = 0x333333FF;           // Hover overlay
        static constexpr Fl_Color PRESSED = 0x404040FF;         // Pressed state
        static constexpr Fl_Color FOCUS = 0x64B5F6FF;           // Focus indicator
        
        // Border colors
        static constexpr Fl_Color BORDER = 0x404040FF;          // Default border
        static constexpr Fl_Color BORDER_FOCUS = 0x1976D2FF;    // Focused border
    };
    
    // Typography scale
    struct Typography {
        static constexpr int HEADLINE_1 = 24;      // Large titles
        static constexpr int HEADLINE_2 = 20;      // Section headers
        static constexpr int HEADLINE_3 = 18;      // Subsection headers
        static constexpr int BODY_1 = 14;          // Primary body text
        static constexpr int BODY_2 = 12;          // Secondary body text
        static constexpr int CAPTION = 10;         // Small text, captions
        static constexpr int BUTTON = 14;          // Button text
    };
    
    // Spacing system (8pt grid)
    struct Spacing {
        static constexpr int UNIT = 8;             // Base unit
        static constexpr int TINY = UNIT / 2;      // 4px
        static constexpr int SMALL = UNIT;         // 8px
        static constexpr int MEDIUM = UNIT * 2;    // 16px
        static constexpr int LARGE = UNIT * 3;     // 24px
        static constexpr int EXTRA_LARGE = UNIT * 4; // 32px
        static constexpr int EXTRA_HUGE = UNIT * 6;  // 48px (renamed from HUGE)
    };
    
    // Component dimensions
    struct Dimensions {
        static constexpr int BUTTON_HEIGHT = 36;
        static constexpr int INPUT_HEIGHT = 40;
        static constexpr int MENU_HEIGHT = 28;
        static constexpr int BUTTON_MIN_WIDTH = 88;
        static constexpr int DIALOG_MIN_WIDTH = 480;
        static constexpr int DIALOG_MIN_HEIGHT = 320;
        static constexpr int MAIN_WINDOW_MIN_WIDTH = 800;
        static constexpr int MAIN_WINDOW_MIN_HEIGHT = 600;
        static constexpr int WINDOW_PADDING = 20;
        static constexpr int FORM_MAX_WIDTH = 400;
    };
    
    // Border radius for rounded corners
    struct BorderRadius {
        static constexpr int SMALL = 4;
        static constexpr int MEDIUM = 8;
        static constexpr int LARGE = 12;
        static constexpr int BUTTON = 6;
        static constexpr int CARD = 8;
    };
    
    // Shadow definitions for depth
    struct Shadow {
        static constexpr int ELEVATION_1 = 1;  // Subtle shadow
        static constexpr int ELEVATION_2 = 2;  // Card shadow
        static constexpr int ELEVATION_3 = 4;  // Dialog shadow
        static constexpr int ELEVATION_4 = 8;  // Menu shadow
    };

public:
    /**
     * @brief Initialize the theme system
     * Sets up custom colors and styling for FLTK
     */
    static void initialize();
    
    /**
     * @brief Apply modern button styling
     * @param button Button widget to style
     * @param variant Button variant (primary, secondary, outlined)
     */
    static void styleButton(Fl_Widget* button, const std::string& variant = "primary");
    
    /**
     * @brief Apply modern input field styling
     * @param input Input widget to style
     * @param hasError Whether the input has validation errors
     */
    static void styleInput(Fl_Widget* input, bool hasError = false);
    
    /**
     * @brief Apply window styling with resizable support
     * @param window Window to style
     * @param isResizable Whether the window should be resizable
     * @param minWidth Minimum width for resizable windows
     * @param minHeight Minimum height for resizable windows
     */
    static void styleWindow(Fl_Window* window, bool isResizable = true, 
                           int minWidth = Dimensions::DIALOG_MIN_WIDTH, 
                           int minHeight = Dimensions::DIALOG_MIN_HEIGHT);
    
    /**
     * @brief Apply text styling
     * @param widget Text widget to style
     * @param variant Text variant (headline1, body1, etc.)
     */
    static void styleText(Fl_Widget* widget, const std::string& variant = "body1");
    
    /**
     * @brief Draw a modern card background
     * @param x X position
     * @param y Y position
     * @param w Width
     * @param h Height
     * @param elevation Shadow elevation (0-4)
     */
    static void drawCard(int x, int y, int w, int h, int elevation = 1);
    
    /**
     * @brief Draw a modern rounded rectangle
     * @param x X position
     * @param y Y position
     * @param w Width
     * @param h Height
     * @param radius Border radius
     * @param color Fill color
     */
    static void drawRoundedRect(int x, int y, int w, int h, int radius, Fl_Color color);
    
    /**
     * @brief Get an appropriate text color for the given background
     * @param backgroundColor Background color
     * @return Appropriate text color (light or dark)
     */
    static Fl_Color getContrastTextColor(Fl_Color backgroundColor);
    
    /**
     * @brief Convert hex color to FLTK color
     * @param hex Hex color string (e.g., "#FF0000")
     * @return FLTK color value
     */
    static Fl_Color hexToFlColor(const std::string& hex);
    
    /**
     * @brief Create a responsive layout that adapts to window size
     * @param window Window to make responsive
     * @param contentCallback Function called when window is resized
     */
    static void makeResponsive(Fl_Window* window, 
                              std::function<void(int width, int height)> contentCallback);
    
    /**
     * @brief Set up window with proper sizing constraints and resizing behavior
     * @param window Window to configure
     * @param isMain Whether this is the main application window
     */
    static void configureWindow(Fl_Window* window, bool isMain = false);
    
    /**
     * @brief Center window on screen
     * @param window Window to center
     */
    static void centerWindow(Fl_Window* window);
    
    /**
     * @brief Apply theme to a window and all its child widgets recursively
     * @param window Window to apply theme to
     */
    static void applyThemeToWindow(Fl_Window* window);
    
    /**
     * @brief Get screen dimensions
     * @return std::pair<width, height> of screen
     */
    static std::pair<int, int> getScreenDimensions();
    
    /**
     * @brief Custom input draw function for modern appearance
     */
    private:
    static bool initialized;
    
    /**
     * @brief Custom button draw function for modern appearance
     */
    static void drawModernButton(Fl_Widget* widget, int x, int y, int w, int h, const std::string& variant);
    
    /**
     * @brief Custom input draw function for modern appearance
     */
    static void drawModernInput(Fl_Widget* widget, int x, int y, int w, int h, bool hasError);
};

#endif // UI_THEME_H
