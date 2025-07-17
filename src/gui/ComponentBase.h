#ifndef COMPONENT_BASE_H
#define COMPONENT_BASE_H

#include <FL/Fl_Widget.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Group.H>
#include <memory>
#include <vector>
#include <functional>
#include <string>

// Type aliases to make callback creation more readable
using ButtonCallback = std::function<void()>;
using TextCallback = std::function<void(const std::string&)>;
using PasswordCallback = std::function<void(const std::string&, const std::string&)>;

// Helper class to manage common callback patterns
// NOTE: This class creates heap-allocated objects that will leak memory unless
// the component is explicitly cleaned up when no longer needed.
// The GuiComponent cleanup() method does not automatically free these resources.
class CallbackHelper {
public:
    template<typename T, typename Func>
    static void setCallback(Fl_Button* button, T* instance, Func callback) {
        // Create a copy of the callback function and store it with the button
        struct CallbackData {
            T* instance;
            Func func;
            CallbackData(T* i, Func f) : instance(i), func(f) {}
        };
        
        // Allocate the data on the heap - FLTK will not delete it
        auto* data = new CallbackData(instance, callback);
        
        // Set up the callback with the combined data
        button->callback([](Fl_Widget* w, void* rawData) {
            auto* data = static_cast<CallbackData*>(rawData);
            if (data && data->instance) {
                data->func(data->instance);
            }
        }, data);
    }
};

#endif // COMPONENT_BASE_H
