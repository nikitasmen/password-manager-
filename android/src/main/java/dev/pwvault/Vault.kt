package dev.pwvault

// The one API the UI talks to, like VaultService on the desktop. Local-first: reads and writes go to the phone's
// store, which syncs with the board on unlock, after every write, and before reads once the last sync is 30 s old.

import org.json.JSONObject
import java.io.File

class Vault(private val local: Store, private val remote: Store?, private val syncState: File) {
    enum class Sync { Disabled, Ok, Offline, Error }

    var status = Sync.Disabled
        private set
    var error = ""
        private set
    private var key: ByteArray? = null
    private val index = mutableMapOf<String, Credential>() // entry id -> decrypted credential
    private val updatedOf = mutableMapOf<String, Long>() // entry id -> record.updated, to keep timestamps increasing
    private var lastSync = 0L

    val unlocked get() = key != null

    /** Is there a vault, here or on the board? A new phone learns about it from the board. */
    @Synchronized fun exists(): Boolean {
        if (local.getMeta() == null) sync()
        return local.getMeta() != null
    }

    @Synchronized fun create(password: String, iterations: Int = DEFAULT_ITERATIONS) {
        check(!exists()) { "a vault already exists" }
        val (meta, vaultKey) = createMeta(password, Alg.AES, iterations)
        local.putMeta(meta, 0)
        useKey(vaultKey)
        sync()
    }

    /** false = wrong password. */
    @Synchronized fun unlock(password: String): Boolean {
        sync() // pick up password changes and entries from other devices first
        val meta = local.getMeta() ?: return false
        useKey(unwrapVaultKey(password, meta) ?: return false)
        return true
    }

    @Synchronized fun lock() {
        key?.fill(0)
        key = null
        index.clear()
        updatedOf.clear()
    }

    private fun useKey(k: ByteArray) {
        lock()
        key = k
        reindex()
    }

    private fun requireKey() = key ?: throw IllegalStateException("vault is locked")

    private fun reindex() {
        val k = requireKey()
        index.clear()
        updatedOf.clear()
        for (r in local.changesAfter(0).entries) {
            updatedOf[r.id] = r.updated
            // one corrupt or tampered record must not lock you out of the rest
            runCatching { openEntry(k, r) }.getOrNull()?.let { index[r.id] = it }
        }
    }

    @Synchronized fun credentials(): List<Credential> {
        requireKey()
        if (remote != null && System.currentTimeMillis() - lastSync > 30_000) sync()
        return index.values.sortedBy { it.platform.lowercase() }
    }

    /** Tells the board's OLED who read what (display only, never blocks a read). */
    @Synchronized fun noteAccess(c: Credential) {
        if (status == Sync.Ok) runCatching { (remote as? EspStore)?.noteAccess(c) }
    }

    private fun nextTimestamp(id: String) = maxOf(System.currentTimeMillis(), (updatedOf[id] ?: 0) + 1)

    @Synchronized fun put(c: Credential) {
        val k = requireKey()
        require(c.platform.isNotEmpty() && c.username.isNotEmpty() && c.password.isNotEmpty()) {
            "Platform, username and password are all required."
        }
        val r = sealEntry(k, c, nextTimestamp(entryId(k, c.platform)))
        // A record the board can't accept (16 KB per request) would block sync forever: refuse it up front
        require(r.json().toString().toByteArray().size <= 12 * 1024) { "Entry too large (keep it under ~8 KB)." }
        local.putEntries(listOf(r))
        reindex()
        sync()
    }

    @Synchronized fun remove(platform: String) {
        val id = entryId(requireKey(), platform)
        if (id !in index) return
        local.putEntries(listOf(tombstone(id, nextTimestamp(id))))
        reindex()
        sync()
    }

    @Synchronized fun verifyMasterPassword(password: String): Boolean {
        val k = requireKey()
        return unwrapVaultKey(password, local.getMeta()!!)?.contentEquals(k) == true
    }

    @Synchronized fun vaultId(): String? = local.getMeta()?.vaultId

    /** A copy of the vault key, for sealing it under another key (fingerprint unlock). Requires unlocked. */
    @Synchronized fun keyCopy(): ByteArray = requireKey().copyOf()

    /** Unlocks with a vault key from elsewhere (fingerprint unlock); false if it doesn't open the stored entries. */
    @Synchronized fun unlockWithKey(k: ByteArray): Boolean {
        sync()
        if (local.getMeta() == null) return false
        val records = local.changesAfter(0).entries.filter { !it.deleted }
        useKey(k.copyOf())
        if (records.isNotEmpty() && index.isEmpty()) return false.also { lock() }
        return true
    }

    @Synchronized fun sealKeyForPin(pinKey: ByteArray): String =
        seal(Alg.AES, pinKey, requireKey(), pinAad(local.getMeta()!!.vaultId))

    /** false = the blob doesn't open this vault. */
    @Synchronized fun unlockWithPinKey(pinKey: ByteArray, blob: String): Boolean {
        sync()
        val meta = local.getMeta() ?: return false
        useKey(try { open(Alg.AES, pinKey, blob, pinAad(meta.vaultId)) } catch (e: DecryptError) { return false })
        return true
    }

    @Synchronized fun sync(): Sync {
        if (remote == null) return Sync.Disabled.also { status = it }
        lastSync = System.currentTimeMillis()
        status = try {
            val changed = syncStores(local, remote, syncState)
            if (changed && unlocked) reindex()
            error = ""
            Sync.Ok
        } catch (e: StoreUnavailable) {
            error = e.message.orEmpty()
            Sync.Offline
        } catch (e: Exception) { // VaultMismatch, a revoked cert, ...: keep working locally, surface it
            error = e.message ?: e.toString()
            Sync.Error
        }
        if (error.isNotEmpty()) System.err.println("pwvault: sync $status: $error") // logcat, tag System.err
        return status
    }
}

// §11: PIN unlock. `pin.json` = {"salt":…,"iter":…,"blob":…}, next to the vault.
sealed interface PinResult {
    object Unlocked : PinResult
    class Wrong(val left: Int) : PinResult
    object Removed : PinResult // gone on the board; pin.json was deleted, use the master password
    class Failed(val why: String) : PinResult
}

fun setPin(vault: Vault, board: EspStore, pinFile: File, master: String, pin: String) {
    require(vault.verifyMasterPassword(master)) { "Wrong master password." }
    require(validPin(pin)) { "Use 4-32 digits." }
    val salt = randomBytes(16)
    val proof = pinProof(pin, salt, DEFAULT_ITERATIONS)
    val blob = vault.sealKeyForPin(pinWrapKey(board.setPin(pinVerifier(proof)), proof))
    val tmp = File(pinFile.path + ".tmp")
    tmp.writeText(JSONObject().put("salt", salt.b64()).put("iter", DEFAULT_ITERATIONS).put("blob", blob).toString())
    check(tmp.renameTo(pinFile)) { "cannot write $pinFile" }
}

fun unlockWithPin(vault: Vault, board: EspStore, pinFile: File, pin: String): PinResult {
    val f = runCatching { JSONObject(pinFile.readText()) }.getOrNull() ?: return PinResult.Failed("No PIN is set.")
    val proof = pinProof(pin, f.getString("salt").unb64(), f.getInt("iter"))
    return when (val r = try { board.tryPin(proof) } catch (e: StoreUnavailable) {
        return PinResult.Failed("The board is unreachable; a PIN needs it. Use the master password.")
    }) {
        is EspStore.PinReply.Wrong -> PinResult.Wrong(r.left)
        EspStore.PinReply.Gone -> PinResult.Removed.also { pinFile.delete() }
        is EspStore.PinReply.Ok ->
            if (vault.unlockWithPinKey(pinWrapKey(r.secret, proof), f.getString("blob"))) PinResult.Unlocked
            else PinResult.Failed("The PIN doesn't open this vault. Use the master password.")
    }
}
