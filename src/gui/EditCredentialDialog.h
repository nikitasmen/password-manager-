#ifndef EDIT_CREDENTIAL_DIALOG_H
#define EDIT_CREDENTIAL_DIALOG_H

#include "GuiComponents.h"
#include "../core/api.h"
#include <FL/Fl_Window.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H>
#include <memory>
#include <string>

class EditCredentialDialog {
private:
    std::unique_ptr<Fl_Window> window;
    std::unique_ptr<ContainerComponent> rootComponent;
    Fl_Input* usernameField;         // Store username field for cleanup
    Fl_Secret_Input* passwordField;  // Store password field for cleanup
    std::string platform;
    std::function<void(bool)> onComplete;
    std::string username;
    CredentialsManager* credManager;

public:
    EditCredentialDialog(const std::string& platform, const std::string& username, 
                        CredentialsManager* credManager, std::function<void(bool)> onComplete)
        : window(nullptr), rootComponent(nullptr), usernameField(nullptr), passwordField(nullptr),
          platform(platform), onComplete(onComplete), username(username), credManager(credManager) {}

    ~EditCredentialDialog() {
        cleanup();
    }

    void show() {
        if (window) {
            window->show();
            return;
        }

        try {
            window = std::make_unique<Fl_Window>(450, 280, ("Update Credentials for " + platform).c_str());
            window->begin();

            rootComponent = std::make_unique<ContainerComponent>(window.get(), 0, 0, 450, 280);
            
            // Display platform name (read-only)
            auto platformDisplay = rootComponent->addChild<DescriptionComponent>(
                window.get(), 25, 20, 400, 25, "Platform: " + platform
            );

            // Username label
            auto usernameLabel = rootComponent->addChild<DescriptionComponent>(
                window.get(), 25, 50, 100, 25, "Username:"
            );
            
            // Create username input field directly using FLTK
            if (!usernameField) {
                usernameField = new Fl_Input(130, 50, 295, 30);
                usernameField->value(username.c_str());
                window->add(usernameField);
            } else {
                usernameField->show();
            }

            // Password label
            auto passwordLabel = rootComponent->addChild<DescriptionComponent>(
                window.get(), 25, 90, 100, 25, "Password:"
            );

            
            // Create password input field directly using FLTK if not already created
            if (!passwordField) {
                passwordField = new Fl_Secret_Input(130, 90, 295, 30);
                passwordField->type(FL_SECRET_INPUT);
                window->add(passwordField);
            } else {
                passwordField->show();
            }

            // Add buttons
            rootComponent->addChild<CredentialDialogButtonsComponent>(
                window.get(), 125, 210, 200, 30,
                [this]() {
                    // Save button callback
                    if (!usernameField || !passwordField) {
                        fl_alert("Input fields not initialized!");
                        return;
                    }
                    
                    std::string newUsername = usernameField->value();
                    std::string newPassword = passwordField->value();
                    
                    if (newUsername.empty()) {
                        fl_alert("Username cannot be empty!");
                        return;
                    }
                    
                    if (newPassword.empty()) {
                        fl_alert("Password cannot be empty!");
                        return;
                    }
                    
                    if (credManager->updateCredentials(platform, newUsername, newPassword)) {
                        fl_message("Credentials updated successfully!");
                        cleanup();
                        if (onComplete) onComplete(true);
                    } else {
                        fl_alert("Failed to update credentials!");
                    }
                },
                [this]() {
                    // Cancel button callback
                    cleanup();
                    if (onComplete) onComplete(false);
                }
            );

            rootComponent->create();
            window->end();
            window->show();
        }
        catch (const std::exception& e) {
            fl_alert("Error creating edit credential dialog: %s", e.what());
            cleanup();
            if (onComplete) onComplete(false);
        }
    }

    void cleanup() {
        if (rootComponent) {
            rootComponent->cleanup();
            rootComponent.reset();
        }
        if (window) {
            if (usernameField) {
                window->remove(usernameField);
                delete usernameField;
                usernameField = nullptr;
            }
            if (passwordField) {
                window->remove(passwordField);
                delete passwordField;
                passwordField = nullptr;
            }
            window->hide();
            window.reset();
        }
    }
};

#endif // EDIT_CREDENTIAL_DIALOG_H