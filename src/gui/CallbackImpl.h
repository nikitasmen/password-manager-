#ifndef CALLBACK_IMPL_H
#define CALLBACK_IMPL_H

#include "ComponentBase.h"
#include "GuiComponent.h"

// Implementation of setCallbackWithCleanup
template <typename T, typename Func>
void CallbackHelper::setCallbackWithCleanup(GuiComponent* component, Fl_Button* button, T* instance, Func callback) {
    void* data = setCallback(button, instance, callback);
    component->registerCallbackData(data);
}

#endif  // CALLBACK_IMPL_H
