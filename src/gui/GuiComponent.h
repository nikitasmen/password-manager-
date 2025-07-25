#ifndef GUI_COMPONENT_H
#define GUI_COMPONENT_H

#include <FL/Fl.H>
#include <FL/Fl_Widget.H>
#include <FL/Fl_Group.H>
#include "ComponentBase.h" // Include first to get CallbackDataBase definition
#include <memory>
#include <vector>
#include <string>

class GuiComponent {
protected:
    Fl_Group* parent;
    int x, y, w, h;
    std::vector<std::unique_ptr<GuiComponent>> children;
    std::vector<Fl_Widget*> widgets;
    std::vector<void*> callbackData;

public:
    GuiComponent(Fl_Group* parent, int x, int y, int w, int h)
        : parent(parent), x(x), y(y), w(w), h(h) {}
    
    virtual ~GuiComponent() {
        cleanup();
    }
    
    virtual void create() = 0;
    
    template<typename T, typename... Args>
    T* addChild(Args&&... args) {
        auto child = std::make_unique<T>(std::forward<Args>(args)...);
        T* ptr = child.get();
        children.push_back(std::move(child));
        return ptr;
    }
    
    template<typename T, typename... Args>
    T* createWidget(Args&&... args) {
        T* widget = new T(std::forward<Args>(args)...);
        widgets.push_back(widget);
        return widget;
    }
    
    void registerCallbackData(void* data) {
        if (data) {
            callbackData.push_back(data);
        }
    }
    
    virtual void cleanup() {
        // First clean up all children recursively
        for (auto& child : children) {
            if (child) {
            child->cleanup();
            }
        }
        children.clear();
        
        // Clean up callback data before widgets
        for (void* data : callbackData) {
            if (data) {
                auto* base = static_cast<CallbackDataBase*>(data);
                delete base;
            }
        }
        callbackData.clear();
        
        // Do NOT manually delete widgets here; let FLTK parent/group handle widget deletion
        widgets.clear();
    }
    
    int getX() const { return x; }
    int getY() const { return y; }
    int getWidth() const { return w; }
    int getHeight() const { return h; }
    Fl_Group* getParent() const { return parent; }
};

#endif // GUI_COMPONENT_H

// Include the callback implementation after GuiComponent is fully defined
#include "CallbackImpl.h"
