package dev.pwvault

// The real screens, driven like a person: tapping and typing in MainActivity. Run through tests/android_test.py.

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onLast
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.printToString
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class UiTest {
    @get:Rule val ui = createAndroidComposeRule<MainActivity>()

    private fun shown(text: String, seconds: Long = 30) = try {
        ui.waitUntil(seconds * 1000) { ui.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty() }
    } catch (e: Throwable) { // what was on screen instead, in the failure message
        throw AssertionError("'$text' never showed; screen ${App.screen}, message '${App.message}':\n" +
            ui.onRoot(useUnmergedTree = false).printToString(), e)
    }

    /** Standalone: create a vault, add an entry, lock, unlock with the master password, and it's still there. */
    @Test fun standaloneVaultThroughTheScreens() {
        shown("Use without a board")
        ui.onNodeWithText("Use without a board").performClick()
        shown("Create vault")
        ui.onNodeWithText("Master password").performTextInput(PW)
        ui.onNodeWithText("Master password again").performTextInput(PW)
        ui.onNodeWithText("Create vault").performClick()
        shown("No entries yet")

        ui.onNodeWithText("Add entry").performClick()
        shown("Site or app")
        ui.onNodeWithText("Site or app").performTextInput("ui.example")
        ui.onNodeWithText("Username or email").performTextInput("me@ui.example")
        ui.onNodeWithText("Password").performTextInput("ui-s3cret")
        ui.onAllNodesWithText("Add entry").onLast().performClick() // the sheet's, over the screen's
        shown("me@ui.example")
        ui.onNodeWithText("ui.example").assertIsDisplayed()
        assertEquals("ui-s3cret", App.items.single { it.platform == "ui.example" }.password)

        ui.onNodeWithText("Lock").performClick()
        shown("Unlock")
        ui.onNodeWithText("Master password").performTextInput("not it")
        ui.onAllNodesWithText("Unlock").onLast().performClick() // the button, under the heading
        shown("That master password doesn't open this vault.")
        ui.onNodeWithText("Master password").performTextInput(PW)
        ui.onAllNodesWithText("Unlock").onLast().performClick() // the button, under the heading
        shown("me@ui.example")
    }
}
