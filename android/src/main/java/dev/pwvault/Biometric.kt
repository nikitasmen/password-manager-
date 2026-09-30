package dev.pwvault

// Fingerprint unlock (PROTOCOL.md §11, client-local unlock): the vault key sealed with an AES key that lives in the
// Android Keystore and works only right after a strong biometric match. Enrolling a new fingerprint on the phone
// destroys that key, and with it this way in. Nothing leaves the phone; the board isn't involved.
// bio.json = {"vault_id":…,"iv":…,"blob":…} (base64), next to the vault.

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class FingerprintsChanged : Exception(
    "The fingerprints on this phone changed, so fingerprint unlock was turned off. Unlock with the master password, " +
        "then turn it on again.",
)

object Biometric {
    private const val ALIAS = "pwvault-bio"

    /** Can this phone do a strong biometric check right now? Never throws: a vendor quirk just means "no". */
    fun available(ctx: Context): Boolean = runCatching { check(ctx) }.getOrDefault(false)

    private fun check(ctx: Context): Boolean = when {
        Build.VERSION.SDK_INT >= 30 -> ctx.getSystemService(BiometricManager::class.java)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        Build.VERSION.SDK_INT == 29 -> @Suppress("DEPRECATION")
            (ctx.getSystemService(BiometricManager::class.java).canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS)
        else -> ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
    }

    private fun keystore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun newKey(): SecretKey = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true) // every use needs a fresh biometric match (no validity window)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= 30) spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        init(spec.build())
        generateKey()
    }

    fun disable(file: File) {
        file.delete()
        runCatching { keystore().deleteEntry(ALIAS) }
    }

    /** A cipher ready to seal (a new key) or to open [file]'s blob; either needs the prompt before use. */
    private fun cipher(file: File, forOpening: Boolean): Cipher = try {
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            if (forOpening) {
                val key = keystore().getKey(ALIAS, null) as? SecretKey ?: throw FingerprintsChanged()
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, JSONObject(file.readText()).getString("iv").unb64()))
            } else init(Cipher.ENCRYPT_MODE, newKey()) // the Keystore picks the IV
        }
    } catch (e: KeyPermanentlyInvalidatedException) {
        disable(file)
        throw FingerprintsChanged()
    }

    /** Shows the system prompt; [done] gets the unlocked cipher, [failed] a message, both on the main thread. */
    private fun prompt(ctx: Context, title: String, c: Cipher, done: (Cipher) -> Unit, failed: (String) -> Unit) {
        BiometricPrompt.Builder(ctx).setTitle(title)
            .setNegativeButton("Use the master password", ctx.mainExecutor) { _, _ -> failed("") }
            .build()
            .authenticate(BiometricPrompt.CryptoObject(c), CancellationSignal(), ctx.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) =
                        r.cryptoObject.cipher?.let(done) ?: failed("The fingerprint check returned no key.")

                    override fun onAuthenticationError(code: Int, msg: CharSequence) =
                        failed(if (code == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
                            code == BiometricPrompt.BIOMETRIC_ERROR_CANCELED) "" else msg.toString())
                })
    }

    /** Turns it on: after a fingerprint, seals [vaultKey] for [vaultId] into [file]. */
    fun enable(ctx: Context, file: File, vaultId: String, vaultKey: ByteArray, done: () -> Unit, failed: (String) -> Unit) {
        val c = try { cipher(file, forOpening = false) } catch (e: Exception) { return failed(e.message.orEmpty()) }
        prompt(ctx, "Turn on fingerprint unlock", c, { unlocked ->
            try {
                unlocked.updateAAD("pwvault-bio:$vaultId".toByteArray())
                val blob = unlocked.doFinal(vaultKey)
                val tmp = File(file.path + ".tmp")
                tmp.writeText(JSONObject().put("vault_id", vaultId).put("iv", unlocked.iv.b64()).put("blob", blob.b64())
                    .toString())
                check(tmp.renameTo(file)) { "couldn't save $file" }
                done()
            } catch (e: Exception) {
                failed(e.message.orEmpty())
            }
        }, failed)
    }

    /** Unlocks: after a fingerprint, gives [done] the vault key sealed in [file] for [vaultId]. */
    fun open(ctx: Context, file: File, vaultId: String, done: (ByteArray) -> Unit, failed: (String) -> Unit) {
        val c = try { cipher(file, forOpening = true) } catch (e: Exception) { return failed(e.message.orEmpty()) }
        prompt(ctx, "Unlock pwvault", c, { unlocked ->
            try {
                val j = JSONObject(file.readText())
                if (j.getString("vault_id") != vaultId) throw IllegalStateException("This fingerprint unlock is for another vault.")
                unlocked.updateAAD("pwvault-bio:$vaultId".toByteArray())
                done(unlocked.doFinal(j.getString("blob").unb64()))
            } catch (e: Exception) {
                failed(e.message ?: "The fingerprint unlock data doesn't open this vault.")
            }
        }, failed)
    }
}
