package dev.pwvault

// Shared by the instrumented tests. They run through tests/android_test.py, which starts two fakes on this
// computer (tests/fake_esp.py: a dedicated board and a server host) and passes their addresses as seen from the
// emulator (10.0.2.2) and their pairing codes. Every test starts with empty app data (the test orchestrator), but
// the fakes are shared: whichever test makes the board's vault first, the others open it with the same password.

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals

const val PW = "correct horse 1"

object TestHosts {
    private fun arg(name: String) = InstrumentationRegistry.getArguments().getString(name)
        ?: throw AssertionError("missing '$name': run these tests through tests/android_test.py")

    val board get() = arg("board") // "10.0.2.2:<port>", pairing on port + 1
    val boardCode get() = arg("boardCode")
    val server get() = arg("server")
    val serverCode get() = arg("serverCode")
}

fun context(): Context = InstrumentationRegistry.getInstrumentation().targetContext

/** App works on its own thread: waits until it's idle and [done] holds. */
fun await(what: String, seconds: Int = 90, done: () -> Boolean) {
    val until = System.currentTimeMillis() + seconds * 1000L
    while (System.currentTimeMillis() < until) {
        if (!App.busy && done()) return
        Thread.sleep(100)
    }
    throw AssertionError("timed out waiting for $what (message: '${App.message}', screen ${App.screen})")
}

/** Pairs with the board, then opens its vault (or makes it, if no test has yet). */
fun pairAndOpen(name: String) {
    App.pair(TestHosts.board, name, TestHosts.boardCode)
    await("pairing with the board") { App.hosts.isNotEmpty() || App.message.isNotEmpty() }
    assertEquals("", App.message)
    App.check()
    await("the vault check") { App.hasVault != null }
    if (App.hasVault == true) App.unlock(PW) else App.create(PW, PW)
    await("the vault to open") { App.screen == Screen.Vault || App.message.isNotEmpty() }
    assertEquals("", App.message)
}
