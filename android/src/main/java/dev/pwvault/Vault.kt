package dev.pwvault

// The one API the UI talks to, like VaultService on the desktop. Local-first: reads and writes go to the phone's
// store, which syncs with the board on unlock, after every write, and before reads once the last sync is 30 s old.

import org.json.JSONObject
import java.io.File

/** A host's role (PROTOCOL.md §6), best first: it decides the sync order and which host gets PINs. */
enum class Role { Dedicated, Server, Peer }

/** As GET /devices says it; unknown = the least trusted. */
fun roleOf(wire: String) = when (wire) { "dedicated" -> Role.Dedicated; "server" -> Role.Server; else -> Role.Peer }

/** One host this phone syncs with. [id]: hex SHA-256 of its pinned server cert, which keys its sync cursors. */
class Host(val id: String, val role: Role, val store: Store)

class Vault(private val local: Store, initialHosts: List<Host>, private val syncState: File) {
    // Mismatch: no host synced, and one holds another vault (see planMerge)
    enum class Sync { Disabled, Ok, Offline, Error, Mismatch }

    /** Each host's result in the last sync. */
    class HostStatus(val host: Host, var status: Sync = Sync.Disabled, var error: String = "", var triedAt: Long = 0)

    private val hosts = mutableListOf<Host>() // best role first
    val hostStatus = mutableListOf<HostStatus>() // parallel to hosts

    init {
        initialHosts.forEach(::addHost)
    }

    /** Pairing with another host: after the hosts with the same or a better role. */
    @Synchronized fun addHost(h: Host) {
        val at = hosts.indexOfFirst { it.role > h.role }.let { if (it < 0) hosts.size else it }
        hosts.add(at, h)
        hostStatus.add(at, HostStatus(h))
    }

    /** Forgetting a host (§10), with its cursors. */
    @Synchronized fun removeHost(id: String) {
        val i = hosts.indexOfFirst { it.id == id }
        if (i >= 0) { hosts.removeAt(i); hostStatus.removeAt(i) }
        forgetCursors(syncState, id)
    }
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
        if (hosts.isNotEmpty() && System.currentTimeMillis() - lastSync > 30_000) sync()
        return index.values.sortedBy { it.platform.lowercase() }
    }

    /** Tells the board's OLED who read what (display only, never blocks a read). */
    @Synchronized fun noteAccess(c: Credential) {
        // to the best host that answered
        val to = hostStatus.firstOrNull { it.status == Sync.Ok }?.host?.store as? EspStore
        runCatching { to?.noteAccess(c) }
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

    /**
     * The board holds another vault (a phone used standalone, then paired). Reads the board's entries with its
     * password and sorts this phone's against them; writes nothing. null = wrong password.
     */
    @Synchronized fun planMerge(boardPassword: String): MergePlan? {
        requireKey()
        val r = mismatched() ?: throw IllegalStateException("No host holds another vault.")
        val meta = r.getMeta() ?: throw IllegalStateException("The board has no vault yet: a sync copies this one there.")
        val k = unwrapVaultKey(boardPassword, meta) ?: return null
        val board = r.changesAfter(0).entries.associateBy { it.id }
        val add = mutableListOf<Pair<Credential, Long>>()
        val conflicts = mutableListOf<Conflict>()
        var same = 0
        for ((id, c) in index.entries.sortedBy { it.value.platform.lowercase() }) {
            val mine = updatedOf.getValue(id)
            val theirs = board[entryId(k, c.platform)]
            val bc = theirs?.let { runCatching { openEntry(k, it) }.getOrNull() }
            when {
                // Only here (or deleted, or unreadable, there): dated past the board's record, or §5 would drop it
                bc == null -> add += c to maxOf(mine, (theirs?.updated ?: 0) + 1)
                bc.username == c.username && bc.password == c.password -> same++
                else -> conflicts += Conflict(c, mine, bc, theirs.updated)
            }
        }
        return MergePlan(k, add, conflicts, same)
    }

    /**
     * Pushes the plan, with [keepPhone] (conflicts where this phone's copy wins), to the board; only once the board
     * has it all, swaps this phone's vault for the board's (the old file stays as vault.pre-merge.json) and opens it.
     */
    @Synchronized fun applyMerge(plan: MergePlan, keepPhone: List<Conflict>) {
        val r = mismatched() ?: throw IllegalStateException("No host holds another vault.")
        val now = System.currentTimeMillis()
        push(r, plan.add.map { (c, t) -> sealEntry(plan.boardKey, c, t) } +
            keepPhone.map { sealEntry(plan.boardKey, it.phone, maxOf(now, it.boardUpdated + 1)) }) // a choice, made now
        val file = (local as LocalStore).file
        if (!file.renameTo(File(file.parentFile, "vault.pre-merge.json"))) throw java.io.IOException("cannot move $file")
        syncState.delete()
        lock()
        if (sync() != Sync.Ok) throw IllegalStateException("The entries are on the board, but this phone couldn't fetch " +
            "its vault yet ($error). Unlock with the board vault's password once it's reachable.")
        useKey(plan.boardKey.copyOf())
    }

    /** The host to merge into: one holding another vault, when none synced (a phone used standalone, then paired). */
    private fun mismatched() = hostStatus.takeIf { s -> s.none { it.status == Sync.Ok } }
        ?.firstOrNull { it.status == Sync.Mismatch }?.host?.store

    /**
     * §8, several hosts: each in turn, best role first, with its own cursors. A change pulled from one host is pushed
     * to the hosts after it in this round, and to the ones before it in the next.
     */
    @Synchronized fun sync(): Sync {
        if (hosts.isEmpty()) return Sync.Disabled.also { status = it }
        val now = System.currentTimeMillis()
        lastSync = now
        var changed = false
        fun syncWith(s: HostStatus) {
            s.triedAt = now
            try {
                changed = syncStores(local, s.host.store, syncState, s.host.id) || changed
                s.status = Sync.Ok
                s.error = ""
            } catch (e: StoreUnavailable) {
                s.status = Sync.Offline
                s.error = e.message.orEmpty()
            } catch (e: VaultMismatch) { // keep working locally until the user merges or forgets the host
                s.status = Sync.Mismatch
                s.error = e.message.orEmpty()
            } catch (e: Exception) { // a revoked cert, ...: keep working locally, surface it
                s.status = Sync.Error
                s.error = e.message ?: e.toString()
            }
            if (s.error.isNotEmpty()) System.err.println("pwvault: sync ${s.host.id.take(8)} ${s.status}: ${s.error}") // logcat
        }
        // One active host per network (§6): one that didn't answer a moment ago is probably elsewhere. Skip it for
        // 5 minutes, unless nothing else syncs (maybe we just came back to its network).
        val (away, here) = hostStatus.partition { it.status == Sync.Offline && now - it.triedAt < 5 * 60_000 }
        here.forEach(::syncWith)
        for (s in away) if (hostStatus.none { it.status == Sync.Ok }) syncWith(s)
        if (changed && unlocked) reindex()
        val worst = listOf(Sync.Ok, Sync.Mismatch, Sync.Error, Sync.Offline) // what the round reports, in this order
            .first { st -> hostStatus.any { it.status == st } }
        status = worst
        error = if (worst == Sync.Ok) "" else hostStatus.first { it.status == worst }.error
        return status
    }
}

/** The same platform in both vaults, with different values. */
class Conflict(val phone: Credential, val phoneUpdated: Long, val board: Credential, val boardUpdated: Long)

/** [add]: only on this phone, with the `updated` to write. [same]: identical in both, left as the board has it. */
class MergePlan(val boardKey: ByteArray, val add: List<Pair<Credential, Long>>, val conflicts: List<Conflict>, val same: Int)

// §11: PIN unlock. `pin.json` = {"salt":…,"iter":…,"blob":…}, next to the vault.
sealed interface PinResult {
    object Unlocked : PinResult
    class Wrong(val left: Int) : PinResult
    object Removed : PinResult // gone on the board; pin.json was deleted, use the master password
    class Failed(val why: String) : PinResult
}

/** [hostId]: the host holding the secret, recorded in pin.json (§11). */
fun setPin(vault: Vault, board: EspStore, pinFile: File, master: String, pin: String, hostId: String = "") {
    require(vault.verifyMasterPassword(master)) { "Wrong master password." }
    require(validPin(pin)) { "Use 4-32 digits." }
    val salt = randomBytes(16)
    val proof = pinProof(pin, salt, DEFAULT_ITERATIONS)
    val blob = vault.sealKeyForPin(pinWrapKey(board.setPin(pinVerifier(proof)), proof))
    val tmp = File(pinFile.path + ".tmp")
    val j = JSONObject().put("salt", salt.b64()).put("iter", DEFAULT_ITERATIONS).put("blob", blob)
    if (hostId.isNotEmpty()) j.put("host", hostId)
    tmp.writeText(j.toString())
    check(tmp.renameTo(pinFile)) { "cannot write $pinFile" }
}

fun unlockWithPin(vault: Vault, board: EspStore, pinFile: File, pin: String, hostId: String = ""): PinResult {
    val f = runCatching { JSONObject(pinFile.readText()) }.getOrNull() ?: return PinResult.Failed("No PIN is set.")
    val owner = f.optString("host")
    if (owner.isNotEmpty() && hostId.isNotEmpty() && owner != hostId)
        return PinResult.Failed("This PIN belongs to another host. Use the master password.")
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
