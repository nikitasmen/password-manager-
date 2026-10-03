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
        fun phone(n: String) = Vault(LocalStore(File(dir, "$n.json")), board, File(dir, "$n-sync.json"))
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

        val other = Vault(LocalStore(File(dir, "other.json")), null, File(dir, "x"))
        other.create("m", iterations = 1000)
        val mixed = Vault(LocalStore(File(dir, "other.json")), board, File(dir, "mixed-sync.json"))
        assertEquals(Vault.Sync.Error, mixed.sync()) // a different vault_id is never merged
    }

    // PWVAULT_TEST_BOARD="host:port,server.pem,device.pem,device.key" (e.g. the desktop's files): read-only, safe on
    // the real board. 30 rounds must reuse one connection; a new TLS session per request ran the board out of RAM.
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
        val storage = esp.storage()
        assertTrue(storage.total > 0 && storage.used <= storage.total && storage.text().contains(" KB of "))
        val phone = Vault(LocalStore(File(dir, "p.json")), esp, File(dir, "p-sync.json"))
        if (!phone.exists()) phone.create("master", iterations = 1000) // a fresh fake; else the vault is someone's
        assertEquals(Vault.Sync.Ok, phone.sync())
        if (!phone.unlock("master")) return // an existing vault with another password: pairing and auth were enough

        phone.put(Credential("phone-test.example", "nik", "s3cret"))
        val second = Vault(LocalStore(File(dir, "p2.json")), esp, File(dir, "p2-sync.json"))
        assertTrue(second.unlock("master"))
        assertEquals("s3cret", second.credentials().first { it.platform == "phone-test.example" }.password)

        val pinFile = File(dir, "pin.json")
        setPin(phone, esp, pinFile, "master", "2468")
        phone.lock()
        assertTrue((unlockWithPin(phone, esp, pinFile, "1111") as PinResult.Wrong).left == 4)
        assertEquals(PinResult.Unlocked, unlockWithPin(phone, esp, pinFile, "2468"))
        assertTrue(phone.unlocked)
        phone.remove("phone-test.example")
    }
}
