#include "UpdateDialog.h"

#include <FL/Fl.H>
#include <FL/fl_ask.H>

#include <unistd.h>

#include <iostream>
#include <sstream>

UpdateDialog::UpdateDialog()
    : statusLabel(nullptr),
      versionLabel(nullptr),
      releaseNotesDisplay(nullptr),
      releaseNotesBuffer(nullptr),
      progressBar(nullptr),
      checkButton(nullptr),
      downloadButton(nullptr),
      closeButton(nullptr),
      updater(std::make_unique<AppUpdater>()),
      updateAvailable(false) {
    setupUI();
}

UpdateDialog::UpdateDialog(const std::string& githubOwner, const std::string& githubRepo)
    : statusLabel(nullptr),
      versionLabel(nullptr),
      releaseNotesDisplay(nullptr),
      releaseNotesBuffer(nullptr),
      progressBar(nullptr),
      checkButton(nullptr),
      downloadButton(nullptr),
      closeButton(nullptr),
      updater(std::make_unique<AppUpdater>(githubOwner, githubRepo)),
      updateAvailable(false) {
    setupUI();
}

UpdateDialog::~UpdateDialog() {
    if (releaseNotesBuffer) {
        delete releaseNotesBuffer;
    }
}

void UpdateDialog::show() {
    if (window) {
        resetUI();
        window->show();
    }
}

void UpdateDialog::hide() {
    if (window) {
        window->hide();
    }
}

bool UpdateDialog::visible() const {
    return window && window->visible();
}

void UpdateDialog::setupUI() {
    // Create main window
    window = std::make_unique<Fl_Window>(500, 400, "Check for Updates");
    window->begin();

    // Current version display
    std::string currentVersionText = "Current Version: " + VersionInfo::getCurrentVersion();
    versionLabel = new Fl_Box(20, 20, 460, 25, currentVersionText.c_str());
    versionLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    versionLabel->copy_label(currentVersionText.c_str());

    // Status label
    statusLabel = new Fl_Box(20, 50, 460, 25, "Click 'Check for Updates' to check for the latest version");
    statusLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);

    // Release notes display
    releaseNotesBuffer = new Fl_Text_Buffer();
    releaseNotesDisplay = new Fl_Text_Display(20, 80, 460, 200);
    releaseNotesDisplay->buffer(releaseNotesBuffer);
    releaseNotesDisplay->box(FL_DOWN_BOX);
    releaseNotesDisplay->textfont(FL_HELVETICA);
    releaseNotesDisplay->textsize(12);
    releaseNotesDisplay->wrap_mode(1, 0);

    // Progress bar (initially hidden)
    progressBar = new Fl_Progress(20, 290, 460, 25);
    progressBar->minimum(0);
    progressBar->maximum(100);
    progressBar->value(0);
    progressBar->hide();

    // Buttons
    checkButton = new Fl_Button(20, 330, 120, 30, "Check for Updates");
    checkButton->callback(checkButtonCallback, this);

    downloadButton = new Fl_Button(160, 330, 120, 30, "Download Update");
    downloadButton->callback(downloadButtonCallback, this);
    downloadButton->deactivate();  // Initially disabled

    closeButton = new Fl_Button(360, 330, 120, 30, "Close");
    closeButton->callback(closeButtonCallback, this);

    window->end();
    window->set_modal();
}

void UpdateDialog::resetUI() {
    statusLabel->label("Click 'Check for Updates' to check for the latest version");
    releaseNotesBuffer->text("");
    progressBar->hide();
    progressBar->value(0);
    checkButton->activate();
    downloadButton->deactivate();
    closeButton->activate();
    updateAvailable = false;

    window->redraw();
}

void UpdateDialog::showCheckingState() {
    statusLabel->label("Checking for updates...");
    checkButton->deactivate();
    downloadButton->deactivate();
    releaseNotesBuffer->text("");

    window->redraw();
    Fl::flush();
}

void UpdateDialog::showUpdateAvailableState(const VersionInfo& versionInfo) {
    std::string statusText = "Update available: " + versionInfo.version;
    statusLabel->copy_label(statusText.c_str());

    // Show release notes
    if (!versionInfo.releaseNotes.empty()) {
        std::string notes = "Release Notes:\n\n" + versionInfo.releaseNotes;
        releaseNotesBuffer->text(notes.c_str());
    } else {
        releaseNotesBuffer->text("No release notes available.");
    }

    checkButton->activate();
    const std::string managed = AppUpdater::packageManagerUpgradeCommand();
    if (managed.empty()) {
        downloadButton->activate();
    } else {
        statusLabel->copy_label((statusText + " - run: " + managed).c_str());
        downloadButton->deactivate();
    }
    updateAvailable = true;
    latestVersion = versionInfo;

    window->redraw();
}

void UpdateDialog::showNoUpdateState() {
    statusLabel->label("You are running the latest version");
    releaseNotesBuffer->text("No updates available.");

    checkButton->activate();
    downloadButton->deactivate();
    updateAvailable = false;

    window->redraw();
}

void UpdateDialog::showDownloadingState() {
    checkButton->deactivate();
    downloadButton->deactivate();
    progressBar->show();
    progressBar->value(0);

    window->redraw();
    Fl::flush();
}

void UpdateDialog::showErrorState(const std::string& message) {
    std::string errorText = "Error: " + message;
    statusLabel->copy_label(errorText.c_str());

    std::string errorNotes = "An error occurred while checking for updates:\n\n" + message;
    releaseNotesBuffer->text(errorNotes.c_str());

    checkButton->activate();
    downloadButton->deactivate();
    progressBar->hide();

    window->redraw();
}

void UpdateDialog::showCompletedState(bool success, const std::string& message) {
    statusLabel->copy_label(message.c_str());

    if (success) {
        releaseNotesBuffer->text(
            "Update completed successfully!\n\nPlease restart the application to use the new version.");
        downloadButton->label("Update Complete");
        downloadButton->deactivate();
    } else {
        std::string errorNotes = "Update failed:\n\n" + message;
        releaseNotesBuffer->text(errorNotes.c_str());
        downloadButton->activate();
    }

    checkButton->activate();
    progressBar->hide();

    window->redraw();
}

// The updater calls back synchronously on this (the GUI) thread, so the callbacks update the dialog directly.
// (Fl::awake would need Fl::lock(), which this app never calls: its callbacks never ran.)
void UpdateDialog::onCheckForUpdates() {
    showCheckingState();
    updater->checkForUpdates([this](bool success, const std::string& message, const VersionInfo& versionInfo) {
        if (!success)
            showErrorState(message);
        else if (versionInfo.isNewerThan(VersionInfo::getCurrentVersion()))
            showUpdateAvailableState(versionInfo);
        else
            showNoUpdateState();
    });
}

void UpdateDialog::onDownloadUpdate() {
    if (!updateAvailable) {
        fl_alert("No update available to download.");
        return;
    }
    showDownloadingState();
    const std::string exe = AppUpdater::executablePath();  // before the install renames over it
    updater->downloadUpdate(
        latestVersion,
        [this](int percentage, const std::string& status) {
            progressBar->value(percentage);
            statusLabel->copy_label((status + " (" + std::to_string(percentage) + "%)").c_str());
            Fl::check();  // repaint while the download blocks this thread
        },
        [this, exe](bool success, const std::string& message) {
            showCompletedState(success, message);
            if (success && fl_choice("Update installed.\n\nRestart the app now?", "Later", "Restart now", nullptr) == 1) {
                execl(exe.c_str(), exe.c_str(), "-g", static_cast<char*>(nullptr));
                fl_alert("Couldn't restart. Start the app again to use the new version.");
            }
        });
}

void UpdateDialog::onClose() {
    hide();
}

// Static callback functions for FLTK
void UpdateDialog::checkButtonCallback(Fl_Widget* widget, void* data) {
    auto* dialog = static_cast<UpdateDialog*>(data);
    dialog->onCheckForUpdates();
}

void UpdateDialog::downloadButtonCallback(Fl_Widget* widget, void* data) {
    auto* dialog = static_cast<UpdateDialog*>(data);
    dialog->onDownloadUpdate();
}

void UpdateDialog::closeButtonCallback(Fl_Widget* widget, void* data) {
    auto* dialog = static_cast<UpdateDialog*>(data);
    dialog->onClose();
}
