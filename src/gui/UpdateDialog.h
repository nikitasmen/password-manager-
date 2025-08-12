#ifndef UPDATE_DIALOG_H
#define UPDATE_DIALOG_H

#include <FL/Fl_Window.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Progress.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Box.H>
#include "UITheme.h"
#include <memory>
#include <functional>
#include "../updater/AppUpdater.h"

/**
 * @class UpdateDialog
 * @brief GUI dialog for checking and downloading application updates
 */
class UpdateDialog {
public:
    /**
     * @brief Default constructor using configuration system
     * Gets GitHub repository information from config file
     */
    UpdateDialog();
    
    /**
     * @brief Constructor with explicit repository information
     * @param githubOwner GitHub repository owner
     * @param githubRepo GitHub repository name
     * @deprecated Use default constructor instead for configuration-based setup
     */
    UpdateDialog(const std::string& githubOwner, const std::string& githubRepo);
    
    /**
     * @brief Destructor
     */
    ~UpdateDialog();
    
    /**
     * @brief Show the update dialog
     */
    void show();
    
    /**
     * @brief Hide the update dialog
     */
    void hide();
    
    /**
     * @brief Check if dialog is currently visible
     */
    bool visible() const;

private:
    // UI Components - Using standard FLTK components with theming
    std::unique_ptr<Fl_Window> window;
    
    Fl_Box* titleLabel;
    Fl_Box* statusLabel;
    Fl_Box* versionLabel;
    Fl_Text_Display* releaseNotesDisplay;
    Fl_Text_Buffer* releaseNotesBuffer;
    Fl_Progress* progressBar;
    Fl_Button* checkButton;
    Fl_Button* downloadButton;
    Fl_Button* closeButton;
    
    // Update functionality
    std::unique_ptr<AppUpdater> updater;
    VersionInfo latestVersion;
    bool updateAvailable;
    
    // UI state management
    void setupUI();
    void resetUI();
    void showCheckingState();
    void showUpdateAvailableState(const VersionInfo& versionInfo);
    void showNoUpdateState();
    void showDownloadingState();
    void showErrorState(const std::string& message);
    void showCompletedState(bool success, const std::string& message);
    
    // Event handlers
    void onCheckForUpdates();
    void onDownloadUpdate();
    void onClose();
    
    // Progress callback for download
    void onDownloadProgress(int percentage, const std::string& status);
};

#endif // UPDATE_DIALOG_H
