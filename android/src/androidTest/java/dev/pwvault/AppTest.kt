package dev.pwvault

// What the JVM tests can't reach: App itself, with Android Keystore keys and its files, against hosts over the
// emulator's network. Run through tests/android_test.py (see TestHosts.kt).

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class AppTest {
    private val prefs get() = context().getSharedPreferences("pwvault", Context.MODE_PRIVATE)

    /** An install from before hosts/ (top of filesDir, prefs) moves into hosts/ on start, and keeps working. */
    @Test fun movesAnOldPairingIntoHosts() {
        val dir = context().filesDir
        val alias = "device-old"
        val keys = App.newDeviceKey(alias)
        val (h, port) = parseHost(TestHosts.board)
        val p = pairWithBoard(h, port + 1, "old-phone", normalizePairCode(TestHosts.boardCode), keys)
        File(dir, "server.der").writeBytes(p.server.encoded)
        File(dir, "device.der").writeBytes(p.cert.encoded)
        prefs.edit().putString("alias", alias).putString("host", TestHosts.board).putString("name", "old-phone").commit()

        App.init(context())

        val host = App.hosts.single()
        assertEquals(sha256(p.server.encoded).hex(), host.id)
        assertEquals(TestHosts.board, host.address)
        assertEquals(Role.Dedicated, host.role)
        assertEquals(alias, host.alias)
        assertEquals(File(dir, "hosts/${host.id.take(16)}"), host.dir)
        val saved = JSONObject(File(host.dir, "host.json").readText())
        assertEquals(TestHosts.board, saved.getString("address"))
        assertEquals("dedicated", saved.getString("role"))
        assertEquals(alias, saved.getString("alias"))
        assertTrue(File(host.dir, "server.der").readBytes().contentEquals(p.server.encoded))
        assertTrue(File(host.dir, "device.der").readBytes().contentEquals(p.cert.encoded))
        assertFalse("the old files are gone", File(dir, "server.der").exists() || File(dir, "device.der").exists())
        assertNull(prefs.getString("alias", null))
        assertNull(prefs.getString("host", null))
        assertEquals("old-phone", prefs.getString("name", null))
        assertTrue("the key stays in the Keystore, now named in host.json", App.keystore().containsAlias(alias))
        assertEquals(Screen.Unlock, App.screen)

        App.check() // the moved pairing still opens a connection the board accepts
        await("the vault check") { App.hasVault != null }
        assertEquals(Vault.Sync.Ok, App.sync)
    }

    /** Pairing, pairing again (which replaces the host), forgetting with a revoke, and the vault staying. */
    @Test fun pairsReplacesAndForgetsAHost() {
        App.init(context())
        assertEquals(Screen.Pair, App.screen)
        pairAndOpen("emu-forget")
        val first = App.hosts.single()
        assertTrue(App.keystore().containsAlias(first.alias))
        App.save(Credential("forget.example", "me", "s3cret"))
        await("saving") { App.items.any { it.platform == "forget.example" } }
        assertEquals(Vault.Sync.Ok, App.sync)

        App.pair(TestHosts.board, "emu-forget", TestHosts.boardCode)
        await("pairing again") { App.hosts.singleOrNull()?.alias != first.alias || App.message.isNotEmpty() }
        assertEquals("", App.message)
        val second = App.hosts.single()
        assertEquals(first.id, second.id)
        assertFalse("the old key is deleted", App.keystore().containsAlias(first.alias))
        assertTrue(App.keystore().containsAlias(second.alias))
        assertEquals(second.alias, JSONObject(File(second.dir, "host.json").readText()).getString("alias"))

        var closed = false
        App.forgetHost(second, revoke = true) { closed = true }
        await("forgetting") { closed || App.message.isNotEmpty() }
        assertEquals("", App.message)
        assertTrue(App.hosts.isEmpty())
        assertFalse(second.dir.exists())
        assertFalse(App.keystore().containsAlias(second.alias))
        assertTrue("with no host left, it keeps working on its own", prefs.getBoolean("standalone", false))
        assertTrue("the vault stays", App.items.any { it.platform == "forget.example" && it.password == "s3cret" })
    }

    /** A dedicated host and a server host: both sync, the PIN goes to the dedicated one (§11). */
    @Test fun twoHostsAndPin() {
        App.init(context())
        pairAndOpen("emu-pin")
        App.startPair()
        App.pair(TestHosts.server, "emu-pin", TestHosts.serverCode)
        await("pairing with the server") { App.hosts.size == 2 || App.message.isNotEmpty() }
        assertEquals("", App.message)
        assertEquals(listOf(Role.Dedicated, Role.Server), App.hosts.map { it.role })
        assertEquals(TestHosts.board, App.pinHost?.address)
        App.syncNow()
        await("syncing both") { App.hostStatus.size == 2 }
        assertEquals(listOf(Vault.Sync.Ok, Vault.Sync.Ok), App.hosts.map { App.hostStatus[it.id] })

        var set = false
        App.setPin(PW, "2468", "2468") { set = true }
        await("setting the PIN") { set || App.message.isNotEmpty() }
        assertEquals("", App.message)
        val pin = JSONObject(App.pinFile.readText())
        assertEquals("pin.json names its host", App.pinHost!!.id, pin.getString("host"))
        assertFalse("and doesn't hold the PIN", pin.toString().contains("2468"))

        App.lock()
        await("locking") { App.screen == Screen.Unlock }
        App.unlockPin("1111")
        await("a wrong PIN") { App.message.isNotEmpty() }
        assertEquals("Wrong PIN. 4 tries left.", App.message)
        App.unlockPin("2468")
        await("the right PIN") { App.screen == Screen.Vault || App.message.isNotEmpty() }
        assertEquals(Screen.Vault, App.screen)
    }

    /** A phone used standalone, then paired with a board that has its own vault: merging moves its entries in. */
    @Test fun mergesAStandaloneVaultIntoTheBoards() {
        // Make sure the board has a vault (a test that ran before may have made it), as another device would
        val seedKeys = App.newDeviceKey("seed")
        val (h, port) = parseHost(TestHosts.board)
        val seed = pairWithBoard(h, port + 1, "emu-seed", normalizePairCode(TestHosts.boardCode), seedKeys)
        val board = EspStore(h, port, seed.server, seedKeys.private, seed.cert)
        val other = Vault(LocalStore(File(context().cacheDir, "seed.json")),
            listOf(Host(sha256(seed.server.encoded).hex(), Role.Dedicated, board)), File(context().cacheDir, "seed.sync"))
        if (!other.exists()) other.create(PW, iterations = 1000)

        App.init(context())
        App.useStandalone()
        App.create("phone only 2", "phone only 2")
        await("the standalone vault") { App.screen == Screen.Vault }
        App.save(Credential("merge.example", "me", "m3rge"))
        await("saving") { App.items.any { it.platform == "merge.example" } }

        App.startPair()
        App.pair(TestHosts.board, "emu-merge", TestHosts.boardCode)
        await("pairing") { App.hosts.isNotEmpty() || App.message.isNotEmpty() }
        assertEquals(Vault.Sync.Mismatch, App.sync)

        App.startMerge()
        App.planMerge("not it")
        await("a wrong board password") { App.message.isNotEmpty() }
        assertEquals("That password doesn't open the board's vault.", App.message)
        App.planMerge(PW)
        await("the merge plan") { App.merge != null || App.message.isNotEmpty() }
        assertTrue(App.merge!!.add.any { it.first.platform == "merge.example" })
        repeat(App.merge!!.conflicts.size) { App.keepPhone += true }
        App.applyMerge()
        await("merging") { App.merge == null && App.screen == Screen.Vault || App.message.isNotEmpty() }
        assertTrue(App.notice, App.notice.startsWith("Merged."))
        assertEquals(Vault.Sync.Ok, App.sync)
        assertTrue(App.items.any { it.platform == "merge.example" && it.password == "m3rge" })
        assertTrue(File(context().filesDir, "vault.pre-merge.json").exists())

        App.lock()
        await("locking") { App.screen == Screen.Unlock }
        App.unlock("phone only 2")
        await("the old password") { App.message.isNotEmpty() }
        App.unlock(PW)
        await("the board's password") { App.screen == Screen.Vault }
    }
}
