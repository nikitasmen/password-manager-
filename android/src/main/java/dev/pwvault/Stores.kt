package dev.pwvault

// docs/PROTOCOL.md §6-9: the two stores (a JSON file on the phone, the board over mutual TLS), pairing, and sync.

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.Socket
import java.net.URL
import java.security.KeyPair
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLException
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager

/** The remote can't be reached: normal when away from home, not an error. */
class StoreUnavailable(message: String, cause: Throwable? = null) : IOException(message, cause)
class VaultMismatch(message: String) : Exception(message)
class PairError(message: String) : Exception(message)

class Changes(val entries: List<Record>, val seq: Long)

interface Store {
    fun getMeta(): Meta?
    fun putMeta(meta: Meta, ifRev: Int): Boolean // compare-and-swap; false = conflict
    fun changesAfter(seq: Long): Changes
    fun putEntries(records: List<Record>) // applies §5, assigns seq
}

/** `vault.json`: {"seq":N,"meta":{…},"entries":{"<id>":{record}}}, replaced atomically on every write. */
class LocalStore(private val file: File) : Store {
    // ponytail: in-process lock only, since this app is the file's one writer; add a file lock if that changes
    private fun load() =
        if (file.exists()) JSONObject(file.readText()) else JSONObject().put("seq", 0).put("entries", JSONObject())

    private fun save(doc: JSONObject) {
        val tmp = File(file.path + ".tmp")
        tmp.writeText(doc.toString())
        if (!tmp.renameTo(file)) throw IOException("cannot replace $file")
    }

    @Synchronized override fun getMeta() = load().optJSONObject("meta")?.let(Meta::of)

    @Synchronized override fun putMeta(meta: Meta, ifRev: Int): Boolean {
        val doc = load()
        if ((doc.optJSONObject("meta")?.getInt("rev") ?: 0) != ifRev) return false
        save(doc.put("meta", meta.json()))
        return true
    }

    @Synchronized override fun changesAfter(seq: Long): Changes {
        val doc = load()
        val entries = doc.getJSONObject("entries")
        return Changes(entries.keys().asSequence().map { Record.of(entries.getJSONObject(it)) }.filter { it.seq > seq }.toList(),
            doc.getLong("seq"))
    }

    @Synchronized override fun putEntries(records: List<Record>) {
        val doc = load()
        val entries = doc.getJSONObject("entries")
        var seq = doc.getLong("seq")
        var changed = false
        for (r in records) {
            val cur = entries.optJSONObject(r.id)?.let(Record::of)
            if (cur != null && !r.isNewer(cur)) continue
            entries.put(r.id, r.copy(seq = ++seq).json())
            changed = true
        }
        if (changed) save(doc.put("seq", seq))
    }
}

/** Trusts exactly [pin], or with a null pin any cert, remembering it (pairing's first look at the board). */
private class PinnedTrust(private val pin: X509Certificate?) : X509TrustManager {
    var seen: X509Certificate? = null
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        seen = chain[0]
        if (pin != null && !chain[0].encoded.contentEquals(pin.encoded)) throw CertificateException("not the paired board")
    }
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = throw CertificateException()
    override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
}

/** Presents the device cert. The key may live in the Android Keystore, so it's used, never exported. */
private class DeviceKey(private val key: PrivateKey, private val cert: X509Certificate) : X509ExtendedKeyManager() {
    var asked = "" // what the TLS stack did with us during the last handshake, for error messages

    private fun choose(t: Array<String>?) = "device".also { asked += "asked(${t?.joinToString("/")}) " }
    override fun chooseClientAlias(t: Array<String>?, i: Array<Principal>?, s: Socket?) = choose(t)
    override fun chooseEngineClientAlias(t: Array<String>?, i: Array<Principal>?, e: SSLEngine?) = choose(t)
    override fun getClientAliases(t: String?, i: Array<Principal>?) = arrayOf("device")
    override fun getCertificateChain(alias: String?) = arrayOf(cert).also { asked += "cert " }
    override fun getPrivateKey(alias: String?) = key.also { asked += "key " }
    override fun chooseServerAlias(t: String?, i: Array<Principal>?, s: Socket?) = null
    override fun getServerAliases(t: String?, i: Array<Principal>?) = null

    /** Can the key sign the way TLS needs? */
    fun selfTest() = listOf("NONEwithECDSA", "SHA256withECDSA").joinToString(" ") { alg ->
        val ok = runCatching {
            java.security.Signature.getInstance(alg).run { initSign(key); update(ByteArray(32)); sign() }
        }
        "$alg:" + (ok.exceptionOrNull()?.let { it.javaClass.simpleName } ?: "ok")
    }
}

private class Http(val status: Int, val body: String) {
    fun json() = JSONObject(body)
    fun error() = runCatching { json().optString("error") }.getOrNull().orEmpty().ifEmpty { "HTTP $status" }
}

private fun tls(trust: PinnedTrust, key: KeyManager?) =
    SSLContext.getInstance("TLS").apply { init(key?.let { arrayOf(it) }, arrayOf(trust), null) }.socketFactory

// The board's cert is named pwvault.local and pinned byte for byte, so "is it the pinned cert" is the name check too,
// even when connecting by IP (what CURLOPT_RESOLVE does on the desktop).
private fun pinnedName(pin: X509Certificate) =
    HostnameVerifier { _, s -> runCatching { s.peerCertificates[0].encoded.contentEquals(pin.encoded) }.getOrDefault(false) }

private fun https(
    host: String, port: Int, method: String, path: String, body: JSONObject?,
    tls: javax.net.ssl.SSLSocketFactory, names: HostnameVerifier, readMs: Int = 15_000,
): Http {
    val c = URL("https", host, port, path).openConnection() as HttpsURLConnection
    c.sslSocketFactory = tls
    c.hostnameVerifier = names
    c.connectTimeout = 1500 // short: "not home" should be detected fast
    c.readTimeout = readMs
    c.requestMethod = method
    if (body != null) {
        c.doOutput = true
        c.setRequestProperty("Content-Type", "application/json")
        c.outputStream.use { it.write(body.toString().toByteArray()) }
    }
    val status = c.responseCode
    val text = (if (status >= 400) c.errorStream else c.inputStream)?.use { String(it.readBytes()) }.orEmpty()
    return Http(status, text)
}

/** Host "a.b.c.d" or "a.b.c.d:port" (443 by default). */
fun parseHost(s: String): Pair<String, Int> {
    val t = s.trim()
    val i = t.lastIndexOf(':')
    return if (i > 0) t.substring(0, i) to (t.substring(i + 1).toIntOrNull() ?: 443) else t to 443
}

/** The board (§7). One instance keeps its socket factory, so HttpsURLConnection reuses the connection. */
class EspStore(
    private val host: String, private val port: Int, private val server: X509Certificate,
    key: PrivateKey, cert: X509Certificate,
) : Store {
    private val device = DeviceKey(key, cert)
    // One factory and one verifier for the store's lifetime: Android pools a keep-alive connection only for requests
    // with the same instances. Fresh ones per request opened a new TLS session each time, and the idle ones left
    // open (~40 KB of RAM each on the board) ran the board out of memory for new handshakes.
    private val factory = tls(PinnedTrust(server), device)
    private val names = pinnedName(server)

    private fun request(method: String, path: String, body: JSONObject? = null): Http {
        device.asked = ""
        val r = try {
            https(host, port, method, path, body, factory, names)
        } catch (e: IOException) {
            // Refused or reset mid-handshake: it's reachable, so say what our side did
            if (e is SSLException || e.message.orEmpty().contains("reset", ignoreCase = true))
                throw IOException("TLS with the board failed (${e.javaClass.simpleName}: ${e.message}). Client cert: " +
                    "${device.asked.trim().ifEmpty { "never asked" }}; key: ${device.selfTest()}. Pair again if it persists.", e)
            throw StoreUnavailable("The board is unreachable at $host:$port (${e.javaClass.simpleName}: ${e.message})", e)
        }
        if (r.status == 403 && r.body.contains("device revoked"))
            throw IOException("This phone was revoked or re-paired on the board. Pair it again.")
        return r
    }

    private fun ok(r: Http, what: String): Http = if (r.status == 200) r else throw IOException("$what: ${r.error()}")

    override fun getMeta(): Meta? {
        val r = request("GET", "/meta")
        return if (r.status == 404) null else Meta.of(ok(r, "GET /meta").json())
    }

    override fun putMeta(meta: Meta, ifRev: Int): Boolean {
        val r = request("PUT", "/meta", JSONObject().put("meta", meta.json()).put("if_rev", ifRev))
        return r.status != 409 && ok(r, "PUT /meta").status == 200
    }

    override fun changesAfter(seq: Long): Changes {
        val j = ok(request("GET", "/entries?after=$seq"), "GET /entries").json()
        val a = j.getJSONArray("entries")
        return Changes((0 until a.length()).map { Record.of(a.getJSONObject(it)) }, j.getLong("seq"))
    }

    override fun putEntries(records: List<Record>) {
        ok(request("POST", "/entries", JSONObject().put("entries", JSONArray(records.map { it.json() }))), "POST /entries")
    }

    fun noteAccess(c: Credential) {
        request("POST", "/access", JSONObject().put("platform", c.platform).put("username", c.username))
    }

    /** §11: the board's secret for this device's new PIN verifier. */
    fun setPin(verifier: String): String =
        ok(request("PUT", "/pin", JSONObject().put("verifier", verifier)), "PUT /pin").json().getString("secret")

    sealed interface PinReply {
        class Ok(val secret: String) : PinReply
        class Wrong(val left: Int) : PinReply
        object Gone : PinReply // 404 or 410: no PIN any more
    }

    fun tryPin(proof: String): PinReply {
        val r = request("POST", "/pin", JSONObject().put("proof", proof))
        return when (r.status) {
            200 -> PinReply.Ok(r.json().getString("secret"))
            403 -> PinReply.Wrong(runCatching { r.json().optInt("left") }.getOrDefault(0))
            404, 410 -> PinReply.Gone
            else -> throw IOException("POST /pin: ${r.error()}")
        }
    }
}

class Paired(val server: X509Certificate, val cert: X509Certificate)

/** §9. [keys] is a fresh P-256 pair; nothing is saved here, the caller keeps what's returned. */
fun pairWithBoard(host: String, pairPort: Int, name: String, code: String, keys: KeyPair): Paired {
    if (!validDeviceName(name)) throw PairError("Use 1-20 characters of a-z, 0-9 and - for the name.")
    if (code.length != 16) throw PairError("The code on the OLED has 16 characters.")

    // The cert the pairing port presents. Unverified here: the macs prove it's the board's.
    val look = PinnedTrust(null)
    try {
        (URL("https", host, pairPort, "/").openConnection() as HttpsURLConnection).run {
            sslSocketFactory = tls(look, null)
            hostnameVerifier = HostnameVerifier { _, _ -> true }
            connectTimeout = 3000
            connect() // the handshake is all we need
            disconnect()
        }
    } catch (e: IOException) {
        throw PairError("The board isn't in pairing mode at $host. Press BOOT on it first: it then shows a code.")
    }
    val server = look.seen ?: throw PairError("The board's certificate couldn't be read.")
    val fp = sha256(server.encoded).hex()
    val csr = certificateRequest(name, keys).b64()
    fun mac(msg: String) = hmac(code.toByteArray(), msg.toByteArray()).hex()

    val body = JSONObject().put("name", name).put("csr", csr).put("mac", mac("pwvault-pair-req\n$fp\n$name\n$csr"))
    val r = try {
        // pinned to the cert just fingerprinted; the board waits up to 60 s for the approving press
        https(host, pairPort, "POST", "/pair", body, tls(PinnedTrust(server), null), pinnedName(server), readMs = 90_000)
    } catch (e: IOException) {
        throw PairError("Lost the board while pairing: ${e.message}.")
    }
    if (r.status != 200) throw PairError("The board said: ${r.error()}. Press BOOT to start over.")
    val j = runCatching { r.json() }.getOrNull()
    val certB64 = j?.optString("cert").orEmpty()
    if (certB64.isEmpty() || j?.optString("mac") != mac("pwvault-pair-resp\n$fp\n$certB64"))
        throw PairError("The reply isn't signed with the code: someone may be intercepting. Nothing was saved.")
    val cert = parseCert(certB64.unb64())
    if (!cert.publicKey.encoded.contentEquals(keys.public.encoded))
        throw PairError("The board signed a different key. Nothing was saved.")
    return Paired(server, cert)
}

fun parseCert(der: ByteArray) = java.security.cert.CertificateFactory.getInstance("X.509")
    .generateCertificate(der.inputStream()) as X509Certificate

// §8. The cursors live in [state]: {"vault_id":…,"local_seq":L,"remote_seq":R}.
private const val BATCH_COUNT = 32
private const val BATCH_BYTES = 12 * 1024

private fun metaWins(a: Meta, b: Meta) = if (a.rev != b.rev) a.rev > b.rev else compareBytes(a.key, b.key) > 0

private fun push(to: Store, entries: List<Record>) {
    val batch = mutableListOf<Record>()
    var bytes = 0
    for (e in entries) {
        val size = e.json().toString().toByteArray().size + 1
        if (batch.isNotEmpty() && (batch.size == BATCH_COUNT || bytes + size > BATCH_BYTES)) {
            to.putEntries(batch.toList())
            batch.clear()
            bytes = 0
        }
        batch += e
        bytes += size
    }
    if (batch.isNotEmpty()) to.putEntries(batch)
}

/** Returns whether the local store changed. */
fun syncStores(local: Store, remote: Store, state: File): Boolean {
    var localChanged = false
    val lm = local.getMeta()
    val rm = remote.getMeta()
    if (lm == null && rm == null) return false
    if (lm != null && rm != null && lm.vaultId != rm.vaultId)
        throw VaultMismatch("The board holds a different vault (vault_id ${rm.vaultId}).")
    if (lm != null && (rm == null || metaWins(lm, rm))) remote.putMeta(lm, rm?.rev ?: 0) // a lost CAS race: next sync
    else if (rm != null && (lm == null || metaWins(rm, lm))) localChanged = local.putMeta(rm, lm?.rev ?: 0)

    val vaultId = (lm ?: rm)!!.vaultId
    val saved = runCatching { JSONObject(state.readText()) }.getOrNull() // missing or corrupt: sync everything
    var localSeq = saved?.optLong("local_seq") ?: 0
    var remoteSeq = saved?.optLong("remote_seq") ?: 0
    // A side that had no vault before this sync has none of the other side's history
    if (saved?.optString("vault_id") != vaultId || lm == null || rm == null) { localSeq = 0; remoteSeq = 0 }

    var theirs = remote.changesAfter(remoteSeq)
    var mine = local.changesAfter(localSeq)
    if (theirs.seq < remoteSeq || mine.seq < localSeq) { // a store's history restarted (restored backup, ...)
        theirs = remote.changesAfter(0)
        mine = local.changesAfter(0)
    }
    push(remote, mine.entries)
    if (theirs.entries.isNotEmpty()) {
        local.putEntries(theirs.entries)
        localChanged = true
    }
    // mine.seq, not the post-pull seq: pulled records echo back once, which §5 ignores (PROTOCOL.md §8 step 6)
    val tmp = File(state.path + ".tmp")
    tmp.writeText(JSONObject().put("vault_id", vaultId).put("local_seq", mine.seq).put("remote_seq", theirs.seq).toString())
    if (!tmp.renameTo(state)) throw IOException("cannot replace $state")
    return localChanged
}
