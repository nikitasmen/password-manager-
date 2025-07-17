#ifndef COMPONENT_BASE_H
#define COMPONENT_BASE_H

#include <FL/Fl_Widget.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Group.H>
#include <memory>
#include <vector>
#include <functional>
#include <string>

// Forward declaration of GuiComponent for use in CallbackHelper
class GuiComponent;

// Type aliases to make callback creation more readable
using ButtonCallback = std::function<void()>;
using TextCallback = std::function<void(const std::string&)>;
using PasswordCallback = std::function<void(const std::string&, const std::string&)>;

// Base class for callback data to enable type erasure
struct CallbackDataBase {
    virtual ~CallbackDataBase() = default;
};

// Helper class to manage common callback patterns
class CallbackHelper {
public:
    template<typename T, typename Func>
    static void* setCallback(Fl_Button* button, T* instance, Func callback) {
        // Create a copy of the callback function and store it with the button
        struct CallbackData : public CallbackDataBase {
            T* instance;
            Func func;
            CallbackData(T* i, Func f) : instance(i), func(f) {}
        };
        
        // Allocate the data on the heap
        auto* data = new CallbackData(instance, callback);
        
        // Set up the callback with the combined data
        button->callback([](Fl_Widget* w, void* rawData) {
            auto* data = static_cast<CallbackData*>(rawData);
            if (data && data->instance) {
                data->func(data->instance);
            }
        }, data);
        
        // Return the data pointer so it can be tracked for cleanup
        return static_cast<void*>(data);
    }
    
    // Declaration of convenience method to set callback and register it with a component
    template<typename T, typename Func>
    static void setCallbackWithCleanup(GuiComponent* component, Fl_Button* button, T* instance, Func callback);
    // The implementation will be provided after GuiComponent is fully defined
};

#endif // COMPONENT_BASE_H
