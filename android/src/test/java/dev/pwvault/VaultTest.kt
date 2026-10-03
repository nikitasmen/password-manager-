package dev.pwvault

// JVM tests: gradle test (from android/, in nix-shell). The vectors are the fixed reference in tests/; a mismatch means
// this code broke the format. PWVAULT_TEST_PAIR="host:mainPort:pairPort,code" also pairs with tests/fake_esp.py
// (never the real board: a wrong code closes its pairing mode) and runs sync and PIN unlock through it.

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

class VaultTest {
    private val v = JSONObject(File("../tests/protocol_vectors.json").readText())
    private val dir = Files.createTempDirectory("pwvault").toFile().apply { deleteOnExit() }

    @Test fun vectors() {
        val vaultKey = v.getString("vault_key_hex").unhex()
        val nonce = v.getString("nonce_hex").unhex()
        for (alg in Alg.entries) {
            val x = v.getJSONObject(alg.wire)
            val meta = Meta.of(x.getJSONObject("meta"))
            val kek = deriveKek(v.getString("password"), meta)
            assertEquals(x.getString("kek_hex"), kek.hex())
            assertEquals(meta.key, seal(alg, kek, vaultKey, "pwvault/v1/key", nonce))
            assertEquals(vaultKey.hex(), unwrapVaultKey(v.getString("password"), meta)!!.hex())
            assertNull(unwrapVaultKey("wrong", meta))

            val cred = Credential("GitHub", "nik", "s3cret", alg)
            val entry = Record.of(x.getJSONObject("entry"))
            assertEquals(entry, sealEntry(vaultKey, cred, v.getLong("updated"), nonce))
            assertEquals(cred, openEntry(vaultKey, entry))
            assertEquals(Meta.of(meta.json()), meta)
        }
        assertEquals(v.getString("entry_id_github"), entryId(v.getString("vault_key_hex").unhex(), "gITHUB"))
        assertEquals("""{"platform":"é\"\\\n\u0001","username":"u","password":"p"}""",
            String(entryPlaintext(Credential("é\"\\\n\u0001", "u", "p"))))
    }

    @Test fun mergeRule() {
        val a = Record("a".repeat(32), 5, false, "aes-256-gcm", "B")
        assertTrue(a.copy(updated = 6).isNewer(a))
        assertTrue(a.copy(data = "C").isNewer(a))
        assertFalse(a.isNewer(a))
        assertFalse(tombstone(a.id, 5).isNewer(a)) // a tombstone loses ties
        assertTrue(compareBytes("é", "z") > 0) // unsigned bytes, not signed
    }

    @Test fun pairingHelpers() {
        assertEquals("ABCD0123EFGH4567", normalizePairCode("abcd-o123-efgh-4567"))
        assertEquals("", normalizePairCode("short"))
        assertEquals("192.168.2.5" to "ABCD0123EFGH4567", parsePairQr("PWVAULT:192.168.2.5:ABCD0123EFGH4567"))
        assertNull(parsePairQr("PWVAULT:192.168.2.5:SHORT"))
        assertEquals("192.168.2.5:8443" to "ABCD0123EFGH4567", parsePairQr("PWVAULT:192.168.2.5:ABCD0123EFGH4567:8443"))
        assertNull(parsePairQr("PWVAULT:192.168.2.5:ABCD0123EFGH4567:x"))
        assertNull(parsePairQr("https://example.com"))
        assertTrue(validDeviceName("phone-2") && !validDeviceName("-x") && !validDeviceName("Phone") && !validDeviceName(""))
        assertTrue(validPin("1234") && !validPin("123") && !validPin("12a4"))
    }

    @Test fun versions() {
        assertTrue(isNewerVersion("v2.1", "2.0") && isNewerVersion("v2.0.1", "2.0") && isNewerVersion("v10.0", "9.9"))
        assertFalse(isNewerVersion("v2.0", "2.0") || isNewerVersion("v1.9", "2.0") || isNewerVersion("v2", "2.0.0"))
    }

    @Test fun twoPhonesSyncThroughOneStore() {
        val board = LocalStore(File(dir, "board.json"))
        fun phone(n: String) = Vault(LocalStore(File(dir, "$n.json")), listOf(Host("board", Role.Dedicated, board)), File(dir, "$n-sync.json"))
        val a = phone("a")
        a.create("master", iterations = 1000)
        a.put(Credential("GitHub", "nik", "v1"))
        val b = phone("b")
        assertTrue(b.exists() && !b.unlock("nope") && b.unlock("master"))
        assertEquals("v1", b.credentials().single().password)
        b.put(Credential("github", "nik", "v2")) // same entry: the id ignores case
        a.sync()
        assertEquals(listOf("v2"), a.credentials().map { it.password })
        val key = a.keyCopy() // fingerprint unlock hands the vault key back like this
        a.lock()
        assertFalse(a.unlockWithKey(randomBytes(32)) || a.unlocked) // a wrong key opens nothing and stays locked
        assertTrue(a.unlockWithKey(key) && a.credentials().single().password == "v2")
        a.remove("GITHUB")
        b.sync()
        assertEquals(emptyList<Credential>(), b.credentials())
        assertEquals(Vault.Sync.Ok, b.status)

        val other = Vault(LocalStore(File(dir, "other.json")), emptyList(), File(dir, "x"))
        other.create("m", iterations = 1000)
        val mixed = Vault(LocalStore(File(dir, "other.json")), listOf(Host("board", Role.Dedicated, board)), File(dir, "mixed-sync.json"))
        assertEquals(Vault.Sync.Mismatch, mixed.sync()) // a different vault_id is never merged by sync
    }

    // PWVAULT_TEST_BOARD="host:port,server.pem,device.pem,device.key" (e.g. the desktop's files): read-only, safe on
    // the real board. 30 rounds must reuse one connection; a new TLS session per request ran the board out of RAM.
    /** A host that can go away. */
    private class Flaky(private val inner: Store) : Store {
        var online = true
        private fun up() { if (!online) throw StoreUnavailable("offline") }
        override fun getMeta() = up().let { inner.getMeta() }
        override fun putMeta(meta: Meta, ifRev: Int) = up().let { inner.putMeta(meta, ifRev) }
        override fun changesAfter(seq: Long) = up().let { inner.changesAfter(seq) }
        override fun putEntries(records: List<Record>) = up().let { inner.putEntries(records) }
    }

    // §8, several hosts: a board and a laptop. The phone has both, the desktop only the board, the pi only the laptop.
    @Test fun severalHosts() {
        val board = LocalStore(File(dir, "h-board.json"))
        val laptop = LocalStore(File(dir, "h-laptop.json"))
        fun device(n: String, vararg to: Pair<String, Store>) = Vault(LocalStore(File(dir, "h-$n.json")),
            to.map { (id, s) -> Host(id, if (id == "board") Role.Dedicated else Role.Peer, s) }, File(dir, "h-$n.sync"))
        val phoneLaptop = Flaky(laptop)
        val phoneBoard = Flaky(board)
        val phone = device("phone", "laptop" to phoneLaptop, "board" to phoneBoard) // worst first
        val desk = device("desk", "board" to board)
        val pi = device("pi", "laptop" to laptop)

        phone.create("master", iterations = 1000)
        assertTrue(board.getMeta() != null && laptop.getMeta() != null)
        assertEquals(listOf("board", "laptop"), phone.hostStatus.map { it.host.id }) // best role first

        assertTrue(pi.unlock("master"))
        pi.put(Credential("Pi", "u", "from-pi"))
        assertTrue(desk.unlock("master"))
        assertTrue(phone.unlock("master"))
        phone.sync() // the board gets what the phone pulled from the laptop after it
        desk.sync()
        assertEquals("from-pi", desk.credentials().single().password)

        phoneLaptop.online = false
        phoneBoard.online = false
        assertEquals(Vault.Sync.Offline, phone.sync())
        phoneLaptop.online = true
        assertEquals(Vault.Sync.Ok, phone.sync())
        assertEquals(listOf(Vault.Sync.Offline, Vault.Sync.Ok), phone.hostStatus.map { it.status })
        phoneBoard.online = true // back on its network: skipped while the laptop answers...
        phone.sync()
        assertEquals(Vault.Sync.Offline, phone.hostStatus[0].status)
        phoneLaptop.online = false // ...and tried at once when nothing else does
        assertEquals(Vault.Sync.Ok, phone.sync())
        assertEquals(Vault.Sync.Ok, phone.hostStatus[0].status)
        phoneLaptop.online = true

        // a host holding another vault is skipped and reported; the round is still Ok
        val stranger = LocalStore(File(dir, "h-stranger.json"))
        Vault(stranger, emptyList(), File(dir, "h-x")).create("x", iterations = 1000)
        File(dir, "h-phone.json").copyTo(File(dir, "h-phone2.json"))
        val phone2 = device("phone2", "board" to board, "stranger" to stranger)
        assertTrue(phone2.unlock("master"))
        assertEquals(Vault.Sync.Ok, phone2.status)
        assertEquals(Vault.Sync.Mismatch, phone2.hostStatus[1].status)
        assertTrue(runCatching { phone2.planMerge("x") }.isFailure) // merging is only for a phone no host takes

        // one cursor pair per host; a v1 cursor file reads as "sync everything"
        val hosts = JSONObject(File(dir, "h-phone.sync").readText()).getJSONObject("hosts")
        assertTrue(hosts.has("board") && hosts.has("laptop"))
        File(dir, "h-desk.sync").writeText("""{"vault_id":"x","local_seq":99,"remote_seq":99}""")
        assertEquals(Vault.Sync.Ok, desk.sync())
        assertTrue(JSONObject(File(dir, "h-desk.sync").readText()).getJSONObject("hosts").has("board"))

        // hosts come and go at runtime: a new one slots in by role, a forgotten one loses its cursors
        val server = LocalStore(File(dir, "h-server.json"))
        desk.addHost(Host("server", Role.Server, server))
        assertEquals(listOf("board", "server"), desk.hostStatus.map { it.host.id })
        assertEquals(Vault.Sync.Ok, desk.sync())
        assertTrue(server.getMeta() != null)
        desk.removeHost("server")
        val left = JSONObject(File(dir, "h-desk.sync").readText()).getJSONObject("hosts")
        assertTrue(desk.hostStatus.size == 1 && !left.has("server") && left.has("board"))
    }

    @Test fun mergeStandalonePhoneIntoBoardVault() {
        val phoneFile = File(dir, "m-phone.json")
        val boardFile = File(dir, "m-board.json")
        Vault(LocalStore(phoneFile), emptyList(), File(dir, "m-s1")).apply {
            create("phone", iterations = 1000)
            put(Credential("a", "u", "p"))
            put(Credential("b", "u", "phone-b"))
            put(Credential("d", "u", "p"))
            put(Credential("x", "u", "p"))
        }
        Thread.sleep(5) // the board's b and x tombstone are newer than the phone's
        val board = Vault(LocalStore(boardFile), emptyList(), File(dir, "m-s2")).apply {
            create("board", iterations = 1000)
            put(Credential("A", "u", "p")) // platforms match ignoring case
            put(Credential("b", "u", "board-b"))
            put(Credential("c", "u", "p"))
            put(Credential("x", "u", "old"))
            remove("x")
        }
        val boardId = board.vaultId()

        val phone = Vault(LocalStore(phoneFile), listOf(Host("board", Role.Dedicated, LocalStore(boardFile))), File(dir, "m-sync"))
        assertTrue(phone.unlock("phone"))
        assertEquals(Vault.Sync.Mismatch, phone.status)
        assertNull(phone.planMerge("phone"))

        val plan = phone.planMerge("board")!!
        assertEquals(1, plan.same)
        assertEquals(listOf("b"), plan.conflicts.map { it.phone.platform })
        assertEquals("board-b", plan.conflicts[0].board.password)
        assertTrue(plan.conflicts[0].boardUpdated > plan.conflicts[0].phoneUpdated)
        assertEquals(listOf("d", "x"), plan.add.map { it.first.platform })

        phone.applyMerge(plan, plan.conflicts) // keep the phone's b although the board's is newer
        assertEquals(Vault.Sync.Ok, phone.status)
        assertEquals(boardId, phone.vaultId())
        assertTrue(File(dir, "vault.pre-merge.json").exists())
        val expect = listOf("A" to "p", "b" to "phone-b", "c" to "p", "d" to "p", "x" to "p")
        assertEquals(expect, phone.credentials().map { it.platform to it.password })
        assertEquals(Vault.Sync.Ok, phone.sync())
        assertTrue(board.unlock("board")) // the board itself has them too, x not lost to its tombstone
        assertEquals(expect, board.credentials().map { it.platform to it.password })
        phone.lock()
        assertTrue(phone.unlock("board")) // the board's password opens this phone now
    }

    @Test fun readOnlyAgainstBoard() {
        val spec = System.getenv("PWVAULT_TEST_BOARD")
        assumeTrue("set PWVAULT_TEST_BOARD to run read-only checks against a board", spec != null)
        val (addr, server, cert, key) = spec!!.split(",")
        val (host, port) = parseHost(addr)
        fun pem(f: String) = File(f).readText().replace(Regex("-----[^-]+-----|\\s"), "").unb64()
        val pk = java.security.KeyFactory.getInstance("EC").generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pem(key)))
        val esp = EspStore(host, port, parseCert(pem(server)), pk, parseCert(pem(cert)))
        repeat(30) {
            esp.getMeta()
            esp.changesAfter(0)
        }
    }

    @Test fun pairSyncAndPinThroughFakeBoard() {
        val spec = System.getenv("PWVAULT_TEST_PAIR")
        assumeTrue("set PWVAULT_TEST_PAIR to run against tests/fake_esp.py", spec != null)
        val (addr, typed) = spec!!.split(",")
        val (host, port, pairPort) = addr.split(":")
        val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val code = normalizePairCode(typed)

        val wrong = runCatching { pairWithBoard(host, pairPort.toInt(), "phone-test", "Z".repeat(16), keys) }
        assertTrue(wrong.exceptionOrNull() is PairError)
        assertTrue(runCatching { pairWithBoard(host, 1, "phone-test", code, keys) }.exceptionOrNull() is PairError)
        val p = pairWithBoard(host, pairPort.toInt(), "phone-test", code, keys)

        val esp = EspStore(host, port.toInt(), p.server, keys.private, p.cert)
        esp.getMeta() // throws unless the board accepts the cert it just issued
        val info = esp.info()
        assertTrue("phone-test" in info.names && info.you == "phone-test")
        val storage = info.storage
        assertTrue(storage.total > 0 && storage.used <= storage.total && storage.text().contains(" KB of "))
        if (info.role != Role.Dedicated) { // §11: only a dedicated host offers PINs
            assertTrue(runCatching { esp.setPin("a".repeat(64)) }.isFailure)
            esp.revokeSelf()
            assertTrue(runCatching { esp.getMeta() }.exceptionOrNull() is DeviceRevoked)
            return
        }
        val phone = Vault(LocalStore(File(dir, "p.json")), listOf(Host("esp", Role.Dedicated, esp)), File(dir, "p-sync.json"))
        if (!phone.exists()) phone.create("master", iterations = 1000) // a fresh fake; else the vault is someone's
        assertEquals(Vault.Sync.Ok, phone.sync())
        if (!phone.unlock("master")) return // an existing vault with another password: pairing and auth were enough

        phone.put(Credential("phone-test.example", "nik", "s3cret"))
        val second = Vault(LocalStore(File(dir, "p2.json")), listOf(Host("esp", Role.Dedicated, esp)), File(dir, "p2-sync.json"))
        assertTrue(second.unlock("master"))
        assertEquals("s3cret", second.credentials().first { it.platform == "phone-test.example" }.password)

        val pinFile = File(dir, "pin.json")
        setPin(phone, esp, pinFile, "master", "2468")
        phone.lock()
        assertTrue((unlockWithPin(phone, esp, pinFile, "1111") as PinResult.Wrong).left == 4)
        assertEquals(PinResult.Unlocked, unlockWithPin(phone, esp, pinFile, "2468"))
        assertTrue(phone.unlocked)
        phone.remove("phone-test.example")
        esp.revokeSelf() // §10: returns once the host refuses this phone
        assertTrue(runCatching { esp.getMeta() }.exceptionOrNull() is DeviceRevoked)
    }
}
