#ifndef GUI_COMPONENT_H
#define GUI_COMPONENT_H

#include <FL/Fl.H>
#include <FL/Fl_Widget.H>
#include <FL/Fl_Group.H>
#include "ComponentBase.h"
#include <memory>
#include <vector>
#include <string>

class GuiComponent {
protected:
    Fl_Group* parent;
    int x, y, w, h;
    std::vector<std::unique_ptr<GuiComponent>> children;
    std::vector<Fl_Widget*> widgets;

public:
    GuiComponent(Fl_Group* parent, int x, int y, int w, int h)
        : parent(parent), x(x), y(y), w(w), h(h) {}
    
    virtual ~GuiComponent() = default;
    
    // Create and render the component
    virtual void create() = 0;
    
    // Add a child component
    template<typename T, typename... Args>
    T* addChild(Args&&... args) {
        auto child = std::make_unique<T>(std::forward<Args>(args)...);
        T* ptr = child.get();
        children.push_back(std::move(child));
        return ptr;
    }
    
    // Add a widget to track
    template<typename T, typename... Args>
    T* createWidget(Args&&... args) {
        T* widget = new T(std::forward<Args>(args)...);
        widgets.push_back(widget);
        return widget;
    }
    
    // Clean up all widgets
    virtual void cleanup() {
        // First clean up all children
        for (auto& child : children) {
            child->cleanup();
        }
        children.clear();
        
        // Then clean up own widgets
        for (auto* widget : widgets) {
            delete widget;
        }
        widgets.clear();
    }
    
    // Getters
    int getX() const { return x; }
    int getY() const { return y; }
    int getWidth() const { return w; }
    int getHeight() const { return h; }
    Fl_Group* getParent() const { return parent; }
};

#endif // GUI_COMPONENT_H
