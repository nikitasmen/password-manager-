package dev.pwvault

// docs/PROTOCOL.md §1-5, §9 and §11 in Kotlin: the shared data types and the pure functions that encrypt, decrypt
// and derive them. No I/O here, so the JVM unit tests check it against tests/protocol_vectors.json.

import org.json.JSONObject
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

const val DEFAULT_ITERATIONS = 600_000
private const val KEY_AAD = "pwvault/v1/key"
private val rng = SecureRandom()

fun randomBytes(n: Int) = ByteArray(n).also(rng::nextBytes)
fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
fun String.unhex() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
fun ByteArray.b64(): String = Base64.getEncoder().encodeToString(this)
fun String.unb64(): ByteArray = Base64.getDecoder().decode(this)
fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
fun hmac(key: ByteArray, msg: ByteArray): ByteArray =
    Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); doFinal(msg) }

/** PBKDF2-HMAC-SHA256, one 32-byte block. Hand-rolled so the password bytes are exactly its UTF-8 (§3). */
fun pbkdf2(password: ByteArray, salt: ByteArray, iterations: Int): ByteArray {
    val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(password, "HmacSHA256")) }
    val u = mac.doFinal(salt + byteArrayOf(0, 0, 0, 1))
    val out = u.copyOf()
    repeat(iterations - 1) {
        mac.update(u)
        mac.doFinal(u, 0)
        for (i in out.indices) out[i] = (out[i].toInt() xor u[i].toInt()).toByte()
    }
    return out
}

/** Bytewise comparison as unsigned bytes of the UTF-8 (§5 and the §8 meta tie-break). */
fun compareBytes(a: String, b: String): Int {
    val x = a.toByteArray()
    val y = b.toByteArray()
    for (i in 0 until minOf(x.size, y.size)) if (x[i] != y[i]) return (x[i].toInt() and 0xff) - (y[i].toInt() and 0xff)
    return x.size - y.size
}

class ProtocolError(message: String) : Exception(message)
class DecryptError : Exception("decryption failed")

// §2
enum class Alg(val wire: String) {
    AES("aes-256-gcm"), CHACHA("chacha20-poly1305");

    companion object {
        fun of(name: String) = entries.firstOrNull { it.wire == name } ?: throw ProtocolError("unsupported cipher: $name")
    }
}

private fun cipher(alg: Alg, mode: Int, key: ByteArray, nonce: ByteArray): Cipher = when (alg) {
    Alg.AES -> Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
    }
    Alg.CHACHA -> chacha().apply { init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce)) }
}

private fun chacha() = try {
    Cipher.getInstance("ChaCha20/Poly1305/NoPadding") // Android (Conscrypt)
} catch (e: GeneralSecurityException) {
    Cipher.getInstance("ChaCha20-Poly1305") // the JDK, for the unit tests
}

fun seal(alg: Alg, key: ByteArray, plain: ByteArray, aad: String, nonce: ByteArray = randomBytes(12)): String {
    val c = cipher(alg, Cipher.ENCRYPT_MODE, key, nonce)
    c.updateAAD(aad.toByteArray())
    return (nonce + c.doFinal(plain)).b64()
}

fun open(alg: Alg, key: ByteArray, blob: String, aad: String): ByteArray {
    val raw = try { blob.unb64() } catch (e: IllegalArgumentException) { throw DecryptError() }
    if (raw.size < 28) throw DecryptError()
    return try {
        val c = cipher(alg, Cipher.DECRYPT_MODE, key, raw.copyOf(12))
        c.updateAAD(aad.toByteArray())
        c.doFinal(raw, 12, raw.size - 12)
    } catch (e: GeneralSecurityException) {
        throw DecryptError()
    }
}

// §3
data class Meta(
    val vaultId: String, val rev: Int, val iter: Int, val salt: String, val alg: String, val key: String,
    val v: Int = 1, val kdf: String = "pbkdf2-sha256",
    val entryAlg: String = "", // the cipher for new entries on every device; "" = aes-256-gcm
) {
    fun json(): JSONObject = JSONObject().put("v", v).put("vault_id", vaultId).put("rev", rev).put("kdf", kdf)
        .put("iter", iter).put("salt", salt).put("alg", alg).put("key", key)
        .apply { if (entryAlg.isNotEmpty()) put("entry_alg", entryAlg) }

    /** The cipher new entries get; an unknown name means AES too (§3). */
    fun entryCipher() = Alg.entries.firstOrNull { it.wire == entryAlg } ?: Alg.AES

    companion object {
        fun of(j: JSONObject) = Meta(
            j.getString("vault_id"), j.getInt("rev"), j.getInt("iter"), j.getString("salt"), j.getString("alg"),
            j.getString("key"), j.getInt("v"), j.getString("kdf"), j.optString("entry_alg", ""),
        )
    }
}

fun deriveKek(password: String, m: Meta): ByteArray {
    if (m.kdf != "pbkdf2-sha256") throw ProtocolError("unsupported kdf: ${m.kdf}")
    return pbkdf2(password.toByteArray(), m.salt.unb64(), m.iter)
}

/** A new vault's meta, and its fresh random vault key. */
fun createMeta(password: String, alg: Alg = Alg.AES, iterations: Int = DEFAULT_ITERATIONS): Pair<Meta, ByteArray> {
    val vaultKey = randomBytes(32)
    val m = Meta(randomBytes(16).hex(), 1, iterations, randomBytes(16).b64(), alg.wire, "")
    return m.copy(key = seal(alg, deriveKek(password, m), vaultKey, KEY_AAD)) to vaultKey
}

/** The vault key, or null for a wrong password (there's no password hash: a password is right if the key opens). */
fun unwrapVaultKey(password: String, m: Meta): ByteArray? = try {
    open(Alg.of(m.alg), deriveKek(password, m), m.key, KEY_AAD)
} catch (e: DecryptError) {
    null
}

// §4
data class Record(
    val id: String, val updated: Long, val deleted: Boolean, val alg: String, val data: String, val seq: Long = 0,
) {
    fun json(): JSONObject = JSONObject().put("id", id).put("updated", updated).put("deleted", deleted)
        .put("alg", alg).put("data", data).put("seq", seq)

    /** §5: does this record replace [cur]? */
    fun isNewer(cur: Record) = if (updated != cur.updated) updated > cur.updated else compareBytes(data, cur.data) > 0

    companion object {
        fun of(j: JSONObject) = Record(
            j.getString("id"), j.getLong("updated"), j.getBoolean("deleted"), j.getString("alg"),
            j.getString("data"), j.optLong("seq", 0),
        )
    }
}

data class Credential(val platform: String, val username: String, val password: String, val alg: Alg = Alg.AES)

fun entryId(vaultKey: ByteArray, platform: String): String {
    val lower = platform.toByteArray().map { if (it in 'A'.code..'Z'.code) (it + 32).toByte() else it }
    return hmac(vaultKey, lower.toByteArray()).copyOf(16).hex()
}

fun entryAad(id: String) = "pwvault/v1/entry/$id"

/** A JSON string as nlohmann::json::dump() writes it, since the vectors pin the plaintext's exact bytes. */
private fun jsonString(s: String) = buildString {
    append('"')
    for (ch in s) when (ch) {
        '"' -> append("\\\"")
        '\\' -> append("\\\\")
        '\b' -> append("\\b")
        '\t' -> append("\\t")
        '\n' -> append("\\n")
        '\u000c' -> append("\\f")
        '\r' -> append("\\r")
        else -> if (ch < ' ') append("\\u%04x".format(ch.code)) else append(ch)
    }
    append('"')
}

fun entryPlaintext(c: Credential) =
    """{"platform":${jsonString(c.platform)},"username":${jsonString(c.username)},"password":${jsonString(c.password)}}"""
        .toByteArray()

fun sealEntry(vaultKey: ByteArray, c: Credential, updated: Long, nonce: ByteArray = randomBytes(12)): Record {
    val id = entryId(vaultKey, c.platform)
    return Record(id, updated, false, c.alg.wire, seal(c.alg, vaultKey, entryPlaintext(c), entryAad(id), nonce))
}

fun tombstone(id: String, updated: Long) = Record(id, updated, true, Alg.AES.wire, "")

/** The credential, or null for a tombstone. Throws for a record that doesn't open. */
fun openEntry(vaultKey: ByteArray, r: Record): Credential? {
    if (r.deleted) return null
    val alg = Alg.of(r.alg)
    val j = JSONObject(String(open(alg, vaultKey, r.data, entryAad(r.id))))
    return Credential(j.getString("platform"), j.getString("username"), j.getString("password"), alg)
}

// §9
fun validDeviceName(n: String) = Regex("[a-z0-9][a-z0-9-]{0,19}").matches(n)

/** The board's pairing QR, `PWVAULT:<ip>:<code>`, as (host, code); null if it isn't one. */
fun parsePairQr(text: String): Pair<String, String>? {
    val parts = text.trim().split(":")
    if (parts.size !in 3..4 || parts[0] != "PWVAULT" || parts[1].isEmpty()) return null
    // §9: a host off the board's ports appends its main port; the address then carries it, "ip:port"
    val port = parts.getOrNull(3)?.let { it.toIntOrNull()?.takeIf { p -> p in 1..65535 } ?: return null }
    return normalizePairCode(parts[2]).ifEmpty { return null }.let { (if (port != null) "${parts[1]}:$port" else parts[1]) to it }
}

/** What the user typed, as the 16-character code, or "" if it isn't one. */
fun normalizePairCode(typed: String): String {
    val code = typed.filter { it != ' ' && it != '-' }.uppercase()
        .map { when (it) { 'I', 'L' -> '1'; 'O' -> '0'; else -> it } }.joinToString("")
    return if (code.length == 16) code else ""
}

private fun der(tag: Int, vararg parts: ByteArray): ByteArray {
    val body = parts.fold(ByteArray(0)) { a, b -> a + b }
    val n = body.size
    val len = when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
        else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
    }
    return byteArrayOf(tag.toByte()) + len + body
}

/** A PKCS#10 request, DER, for CN=[name] and the P-256 key pair (Android has no CSR builder). */
fun certificateRequest(name: String, keys: KeyPair): ByteArray {
    val cn = der(0x30, der(0x06, byteArrayOf(0x55, 0x04, 0x03)), der(0x13, name.toByteArray()))
    val info = der(0x30, der(0x02, byteArrayOf(0)), der(0x30, der(0x31, cn)), keys.public.encoded, der(0xA0))
    val sig = Signature.getInstance("SHA256withECDSA").run { initSign(keys.private); update(info); sign() }
    val ecdsaSha256 = byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x04, 0x03, 0x02)
    return der(0x30, info, der(0x30, der(0x06, ecdsaSha256)), der(0x03, byteArrayOf(0), sig))
}

// §11
fun validPin(pin: String) = pin.length in 4..32 && pin.all { it in '0'..'9' }
fun pinProof(pin: String, salt: ByteArray, iterations: Int) = pbkdf2(pin.toByteArray(), salt, iterations).hex()
fun pinVerifier(proof: String) = sha256(proof.toByteArray()).hex()
fun pinWrapKey(secretHex: String, proof: String) = hmac(secretHex.toByteArray(), "pwvault-pin-key\n$proof".toByteArray())
fun pinAad(vaultId: String) = "pwvault-pin:$vaultId"
