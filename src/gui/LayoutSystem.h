#ifndef LAYOUT_SYSTEM_H
#define LAYOUT_SYSTEM_H

#include "UITheme.h"
#include <FL/Fl_Group.H>
#include <FL/Fl_Widget.H>
#include <vector>
#include <memory>
#include <functional>

/**
 * @class LayoutContainer
 * @brief Base class for layout containers with automatic spacing and alignment
 */
class LayoutContainer : public Fl_Group {
protected:
    int padding;
    int spacing;
    
public:
    LayoutContainer(int x, int y, int w, int h, int padding = UITheme::Spacing::MEDIUM)
        : Fl_Group(x, y, w, h), padding(padding), spacing(UITheme::Spacing::SMALL) {
        box(FL_NO_BOX);
    }
    
    virtual void layoutChildren() = 0;
    
    void setPadding(int newPadding) {
        padding = newPadding;
        layoutChildren();
    }
    
    void setSpacing(int newSpacing) {
        spacing = newSpacing;
        layoutChildren();
    }
    
    // Override add to trigger layout
    void add(Fl_Widget* widget) {
        Fl_Group::add(widget);
        layoutChildren();
    }
    
    // Override resize to trigger layout
    void resize(int x, int y, int w, int h) {
        Fl_Group::resize(x, y, w, h);
        layoutChildren();
    }
};

/**
 * @class VBoxLayout
 * @brief Vertical box layout - arranges children vertically with consistent spacing
 */
class VBoxLayout : public LayoutContainer {
private:
    enum Alignment { LEFT, CENTER, RIGHT, STRETCH };
    Alignment alignment;
    
public:
    VBoxLayout(int x, int y, int w, int h, Alignment align = CENTER)
        : LayoutContainer(x, y, w, h), alignment(align) {}
    
    void layoutChildren() override {
        if (children() == 0) return;
        
        int contentWidth = w() - (2 * padding);
        int currentY = y() + padding;
        
        for (int i = 0; i < children(); i++) {
            Fl_Widget* child = this->child(i);
            if (!child->visible()) continue;
            
            int childX, childW;
            
            switch (alignment) {
                case LEFT:
                    childX = x() + padding;
                    childW = child->w();
                    break;
                case RIGHT:
                    childX = x() + w() - padding - child->w();
                    childW = child->w();
                    break;
                case STRETCH:
                    childX = x() + padding;
                    childW = contentWidth;
                    break;
                case CENTER:
                default:
                    childX = x() + padding + (contentWidth - child->w()) / 2;
                    childW = child->w();
                    break;
            }
            
            child->resize(childX, currentY, childW, child->h());
            currentY += child->h() + spacing;
        }
    }
    
    void setAlignment(Alignment align) {
        alignment = align;
        layoutChildren();
    }
    
    // Calculate minimum height needed for all children
    int getMinimumHeight() const {
        int totalHeight = 2 * padding;
        int visibleChildren = 0;
        
        for (int i = 0; i < children(); i++) {
            if (this->child(i)->visible()) {
                totalHeight += this->child(i)->h();
                visibleChildren++;
            }
        }
        
        if (visibleChildren > 0) {
            totalHeight += (visibleChildren - 1) * spacing;
        }
        
        return totalHeight;
    }
};

/**
 * @class HBoxLayout
 * @brief Horizontal box layout - arranges children horizontally with consistent spacing
 */
class HBoxLayout : public LayoutContainer {
private:
    enum Alignment { TOP, MIDDLE, BOTTOM, STRETCH };
    Alignment alignment;
    
public:
    HBoxLayout(int x, int y, int w, int h, Alignment align = MIDDLE)
        : LayoutContainer(x, y, w, h), alignment(align) {}
    
    void layoutChildren() override {
        if (children() == 0) return;
        
        int contentHeight = h() - (2 * padding);
        int currentX = x() + padding;
        
        for (int i = 0; i < children(); i++) {
            Fl_Widget* child = this->child(i);
            if (!child->visible()) continue;
            
            int childY, childH;
            
            switch (alignment) {
                case TOP:
                    childY = y() + padding;
                    childH = child->h();
                    break;
                case BOTTOM:
                    childY = y() + h() - padding - child->h();
                    childH = child->h();
                    break;
                case STRETCH:
                    childY = y() + padding;
                    childH = contentHeight;
                    break;
                case MIDDLE:
                default:
                    childY = y() + padding + (contentHeight - child->h()) / 2;
                    childH = child->h();
                    break;
            }
            
            child->resize(currentX, childY, child->w(), childH);
            currentX += child->w() + spacing;
        }
    }
    
    void setAlignment(Alignment align) {
        alignment = align;
        layoutChildren();
    }
    
    // Calculate minimum width needed for all children
    int getMinimumWidth() const {
        int totalWidth = 2 * padding;
        int visibleChildren = 0;
        
        for (int i = 0; i < children(); i++) {
            if (this->child(i)->visible()) {
                totalWidth += this->child(i)->w();
                visibleChildren++;
            }
        }
        
        if (visibleChildren > 0) {
            totalWidth += (visibleChildren - 1) * spacing;
        }
        
        return totalWidth;
    }
};

/**
 * @class GridLayout
 * @brief Grid layout - arranges children in a grid with consistent spacing
 */
class GridLayout : public LayoutContainer {
private:
    int columns;
    int rows;
    bool autoRows;
    
public:
    GridLayout(int x, int y, int w, int h, int cols, int rows = -1)
        : LayoutContainer(x, y, w, h), columns(cols), rows(rows), autoRows(rows == -1) {}
    
    void layoutChildren() override {
        if (children() == 0 || columns <= 0) return;
        
        int actualRows = autoRows ? (children() + columns - 1) / columns : rows;
        if (actualRows <= 0) return;
        
        int contentWidth = w() - (2 * padding);
        int contentHeight = h() - (2 * padding);
        
        int cellWidth = (contentWidth - (columns - 1) * spacing) / columns;
        int cellHeight = (contentHeight - (actualRows - 1) * spacing) / actualRows;
        
        for (int i = 0; i < children() && i < columns * actualRows; i++) {
            Fl_Widget* child = this->child(i);
            if (!child->visible()) continue;
            
            int col = i % columns;
            int row = i / columns;
            
            int childX = x() + padding + col * (cellWidth + spacing);
            int childY = y() + padding + row * (cellHeight + spacing);
            
            child->resize(childX, childY, cellWidth, cellHeight);
        }
    }
    
    void setColumns(int cols) {
        columns = cols;
        layoutChildren();
    }
    
    void setRows(int rowCount) {
        rows = rowCount;
        autoRows = (rowCount == -1);
        layoutChildren();
    }
};

/**
 * @class FormLayout
 * @brief Specialized layout for forms with labels and inputs
 */
class FormLayout : public VBoxLayout {
private:
    int labelWidth;
    int inputSpacing;
    
public:
    FormLayout(int x, int y, int w, int h, int labelWidth = 120)
        : VBoxLayout(x, y, w, h), labelWidth(labelWidth), 
          inputSpacing(UITheme::Spacing::MEDIUM) {}
    
    // Add a form row with label and input
    void addFormRow(const std::string& labelText, Fl_Widget* input, 
                   const std::string& helpText = "") {
        
        // Create a horizontal container for this row
        int rowHeight = std::max(input->h(), UITheme::Dimensions::INPUT_HEIGHT);
        if (!helpText.empty()) {
            rowHeight += UITheme::Typography::CAPTION + UITheme::Spacing::TINY;
        }
        
        HBoxLayout* row = new HBoxLayout(0, 0, w() - 2 * padding, rowHeight);
        
        // Create label
        Fl_Box* label = new Fl_Box(0, 0, labelWidth, input->h(), labelText.c_str());
        UITheme::styleText(label, "body1");
        label->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        row->add(label);
        
        // Add input
        input->size(w() - 2 * padding - labelWidth - inputSpacing, input->h());
        row->add(input);
        
        // Add help text if provided
        if (!helpText.empty()) {
            Fl_Box* help = new Fl_Box(labelWidth + inputSpacing, input->h() + UITheme::Spacing::TINY, 
                                     w() - 2 * padding - labelWidth - inputSpacing, 
                                     UITheme::Typography::CAPTION, helpText.c_str());
            UITheme::styleText(help, "caption");
            help->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
            row->add(help);
        }
        
        add(row);
    }
    
    void setLabelWidth(int width) {
        labelWidth = width;
        layoutChildren();
    }
};

/**
 * @class ResponsiveLayout
 * @brief Layout that adapts to different screen sizes
 */
class ResponsiveLayout : public LayoutContainer {
private:
    enum BreakPoint { SMALL, MEDIUM, LARGE };
    BreakPoint currentBreakPoint;
    
    std::function<void(BreakPoint)> layoutFunction;
    
    static constexpr int SMALL_BREAKPOINT = 480;
    static constexpr int MEDIUM_BREAKPOINT = 768;
    
public:
    ResponsiveLayout(int x, int y, int w, int h)
        : LayoutContainer(x, y, w, h) {
        updateBreakPoint();
    }
    
    void layoutChildren() override {
        updateBreakPoint();
        if (layoutFunction) {
            layoutFunction(currentBreakPoint);
        }
    }
    
    void setLayoutFunction(std::function<void(BreakPoint)> func) {
        layoutFunction = func;
        layoutChildren();
    }
    
    BreakPoint getCurrentBreakPoint() const {
        return currentBreakPoint;
    }
    
private:
    void updateBreakPoint() {
        if (w() < SMALL_BREAKPOINT) {
            currentBreakPoint = SMALL;
        } else if (w() < MEDIUM_BREAKPOINT) {
            currentBreakPoint = MEDIUM;
        } else {
            currentBreakPoint = LARGE;
        }
    }
};

#endif // LAYOUT_SYSTEM_H
