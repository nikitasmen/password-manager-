#ifndef EDIT_CREDENTIAL_DIALOG_H
#define EDIT_CREDENTIAL_DIALOG_H

#include <FL/Fl_Choice.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/Fl_Window.H>

#include <functional>
#include <memory>
#include <string>

#include "../utils/EncryptionUtils.h"
#include "../vault/VaultFormat.h"
#include "GuiComponents.h"

// Pure view: collects new username/password/cipher and hands them to `onSave`. It never touches the vault itself.
class EditCredentialDialog {
   public:
    using SaveFn = std::function<bool(const std::string& username, const std::string& password, CipherAlg alg)>;

   private:
    std::unique_ptr<Fl_Window> window;
    std::unique_ptr<ContainerComponent> rootComponent;
    Fl_Input* usernameField;  // owned by `window`
    Fl_Secret_Input* passwordField;
    Fl_Choice* encryptionChoice;
    Credential current;
    SaveFn onSave;
    std::function<void(bool)> onComplete;

   public:
    EditCredentialDialog(Credential current, SaveFn onSave, std::function<void(bool)> onComplete)
        : window(nullptr),
          rootComponent(nullptr),
          usernameField(nullptr),
          passwordField(nullptr),
          encryptionChoice(nullptr),
          current(std::move(current)),
          onSave(std::move(onSave)),
          onComplete(std::move(onComplete)) {
    }

    ~EditCredentialDialog() {
        cleanup();
    }

    void show() {
        if (window) {
            window->show();
            return;
        }

        try {
            window = std::make_unique<Fl_Window>(450, 320, ("Update Credentials for " + current.platform).c_str());
            window->begin();

            rootComponent = std::make_unique<ContainerComponent>(window.get(), 0, 0, 450, 320);

            rootComponent->addChild<DescriptionComponent>(window.get(), 25, 20, 400, 25, "Platform: " + current.platform);

            rootComponent->addChild<DescriptionComponent>(window.get(), 25, 50, 100, 25, "Username:");
            usernameField = new Fl_Input(130, 50, 295, 30);
            usernameField->value(current.username.c_str());
            window->add(usernameField);

            rootComponent->addChild<DescriptionComponent>(window.get(), 25, 90, 100, 25, "Password:");
            passwordField = new Fl_Secret_Input(130, 90, 295, 30);
            passwordField->type(FL_SECRET_INPUT);
            window->add(passwordField);

            rootComponent->addChild<DescriptionComponent>(window.get(), 25, 130, 100, 25, "Encryption:");
            encryptionChoice = new Fl_Choice(130, 130, 295, 30);
            for (CipherAlg alg : allCiphers())
                encryptionChoice->add(encryption_utils::getDisplayName(alg));
            encryptionChoice->value(encryption_utils::toDropdownIndex(current.alg));  // keep what the entry uses
            window->add(encryptionChoice);

            rootComponent->addChild<CredentialDialogButtonsComponent>(
                window.get(),
                125,
                250,
                200,
                30,
                [this]() {
                    std::string newUsername = usernameField->value();
                    std::string newPassword = passwordField->value();
                    CipherAlg alg = encryption_utils::fromDropdownIndex(encryptionChoice->value());

                    if (newUsername.empty()) {
                        fl_alert("Username cannot be empty!");
                        return;
                    }
                    if (newPassword.empty()) {
                        fl_alert("Password cannot be empty!");
                        return;
                    }
                    if (onSave(newUsername, newPassword, alg)) {
                        fl_message("Credentials updated successfully!");
                        auto done = onComplete;  // cleanup() may be followed by the owner deleting us
                        cleanup();
                        if (done) done(true);
                    } else {
                        fl_alert("Failed to update credentials!");
                    }
                },
                [this]() {
                    auto done = onComplete;
                    cleanup();
                    if (done) done(false);
                });

            rootComponent->create();
            window->end();
            window->show();
        } catch (const std::exception& e) {
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
            window->hide();
            window.reset();  // Fl_Group's destructor deletes the child inputs too
            usernameField = nullptr;
            passwordField = nullptr;
            encryptionChoice = nullptr;
        }
    }
};

#endif  // EDIT_CREDENTIAL_DIALOG_H
