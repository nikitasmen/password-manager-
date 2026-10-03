package dev.pwvault

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import kotlinx.coroutines.delay
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

private const val PAIR_PORT = 8444 // PROTOCOL.md §9

enum class Screen { Pair, Unlock, Vault }

/**
 * App state lives here, not in the activity, so a rotation keeps it. Every vault call runs on one worker thread, in
 * order. Files (filesDir): vault.json, sync.json, pin.json, server.der (the pinned board cert), device.der; the
 * device key is in the Android Keystore and never leaves it.
 *
 * The demo build (applicationIdSuffix .demo) keeps a local-only vault of its own and allows screenshots, for
 * working on the UI without the board or the real vault.
 */
object App {
    private lateinit var dir: File
    private lateinit var prefs: SharedPreferences
    private var vault: Vault? = null
    private var board: EspStore? = null
    private val worker = Executors.newSingleThreadExecutor()
    val pinFile get() = File(dir, "pin.json")
    val bioFile get() = File(dir, "bio.json")
    private val main = Handler(Looper.getMainLooper())
    val host get() = prefs.getString("host", "").orEmpty()
    val deviceName get() = prefs.getString("name", "phone").orEmpty()
    val paired get() = vault != null
    val hasBoard get() = board != null

    var screen by mutableStateOf(Screen.Pair)
    var hasVault by mutableStateOf<Boolean?>(null) // null = not checked yet
    var sync by mutableStateOf(Vault.Sync.Disabled)
    var syncedAt by mutableStateOf<Long?>(null)
    var syncError by mutableStateOf("")
    var busy by mutableStateOf(false)
    var syncing by mutableStateOf(false)
    var pairing by mutableStateOf(false)
    var message by mutableStateOf("") // what went wrong, and what to do about it
    var notice by mutableStateOf("") // what just worked
    var items by mutableStateOf(listOf<Credential>())
    var bioOn by mutableStateOf(false) // fingerprint unlock is set up (bio.json)
    var update by mutableStateOf<Release?>(null) // a newer release with an APK
    var updating by mutableStateOf<Int?>(null) // download progress, %
    var storage by mutableStateOf("") // the board's flash use, for Settings

    fun init(ctx: Context) {
        if (::dir.isInitialized) return
        dir = ctx.filesDir
        prefs = ctx.getSharedPreferences("pwvault", Context.MODE_PRIVATE)
        bioOn = bioFile.exists()
        if (BuildConfig.DEMO) {
            vault = Vault(LocalStore(File(dir, "vault.json")), null, File(dir, "sync.json"))
            screen = Screen.Unlock
        } else load()
    }

    private fun keystore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun newDeviceKey(alias: String): KeyPair =
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512)
                    .build(),
            )
            generateKeyPair()
        }

    private fun load() {
        val key = prefs.getString("alias", null)?.let { keystore().getKey(it, null) as? PrivateKey }
        val server = File(dir, "server.der")
        val cert = File(dir, "device.der")
        if (key == null || !server.exists() || !cert.exists()) return
        val (h, p) = parseHost(host)
        board = EspStore(h, p, parseCert(server.readBytes()), key, parseCert(cert.readBytes()))
        vault = Vault(LocalStore(File(dir, "vault.json")), board, File(dir, "sync.json"))
        hasVault = null
        screen = Screen.Unlock
    }

    private fun run(task: () -> Unit) {
        busy = true
        message = ""
        notice = ""
        worker.execute {
            try {
                task()
            } catch (e: Exception) {
                message = e.message ?: e.toString()
            } finally {
                busy = false
                syncing = false
                pairing = false
            }
        }
    }

    private fun showStatus() {
        val v = vault ?: return
        sync = v.status
        syncError = v.error
        if (v.status == Vault.Sync.Ok) syncedAt = System.currentTimeMillis()
    }

    private fun opened() {
        items = vault!!.credentials()
        showStatus()
        screen = Screen.Vault
        if (System.currentTimeMillis() - prefs.getLong("updateCheckedAt", 0) > 24 * 3600_000L) checkUpdate(manual = false)
    }

    /** Off the vault's worker: GitHub can be slow, and a vault call shouldn't wait behind it. */
    fun checkUpdate(manual: Boolean) {
        if (BuildConfig.DEMO) return
        Thread {
            try {
                val r = Updater.latest()
                prefs.edit().putLong("updateCheckedAt", System.currentTimeMillis()).apply()
                val newer = isNewerVersion(r.version, BuildConfig.VERSION_NAME)
                update = if (newer && r.apkUrl != null) r else null
                if (manual) notice = when {
                    newer && r.apkUrl == null -> "${r.version} is out, but has no Android build yet."
                    newer -> ""
                    else -> "pwvault ${BuildConfig.VERSION_NAME} is the latest version."
                }
            } catch (e: Exception) {
                if (manual) message = "Couldn't check for updates: ${e.message}"
            }
        }.start()
    }

    fun installUpdate(ctx: Context) {
        val r = update ?: return
        if (!Updater.canInstall(ctx)) {
            notice = "Allow pwvault to install updates, then tap Update again."
            ctx.startActivity(Updater.allowIntent(ctx))
            return
        }
        updating = 0
        Thread {
            try {
                Updater.install(ctx.applicationContext, r) { updating = it }
            } catch (e: Exception) {
                updating = null
                message = "The update didn't download: ${e.message}"
            }
        }.start()
    }

    fun check() = run {
        val exists = vault!!.exists()
        showStatus()
        hasVault = exists
    }

    fun pair(hostText: String, name: String, typed: String) {
        pairing = true
        run {
            val code = normalizePairCode(typed)
            if (code.isEmpty()) throw PairError("The code on the board has 16 characters. Check it and try again.")
            val alias = "device-${System.currentTimeMillis()}"
            val keys = newDeviceKey(alias)
            val p = try {
                pairWithBoard(parseHost(hostText).first, PAIR_PORT, name, code, keys)
            } catch (e: Exception) {
                keystore().deleteEntry(alias)
                throw e
            }
            File(dir, "server.der").writeBytes(p.server.encoded)
            File(dir, "device.der").writeBytes(p.cert.encoded)
            prefs.getString("alias", null)?.let { keystore().deleteEntry(it) }
            prefs.edit().putString("host", hostText.trim()).putString("alias", alias).putString("name", name).commit()
            pinFile.delete() // re-pairing deleted this name's PIN on the board
            load()
        }
    }

    fun create(password: String, repeat: String) = run {
        require(password.isNotEmpty() && password == repeat) { "The two passwords don't match." }
        vault!!.create(password)
        opened()
    }

    fun unlock(password: String) = run {
        if (!vault!!.unlock(password)) throw Exception("That master password doesn't open this vault.")
        opened()
    }

    fun unlockPin(pin: String) = run {
        when (val r = unlockWithPin(vault!!, board!!, pinFile, pin)) {
            PinResult.Unlocked -> opened()
            is PinResult.Wrong -> message = if (r.left == 1) "Wrong PIN. 1 try left before the PIN is deleted."
                else "Wrong PIN. ${r.left} tries left."
            PinResult.Removed -> message = "The PIN was deleted after too many tries, or when this phone was paired " +
                "again. Unlock with the master password."
            is PinResult.Failed -> message = r.why
        }
    }

    fun setPin(master: String, pin: String, repeat: String, done: () -> Unit) = run {
        require(validPin(pin)) { "A PIN is 4 to 32 digits." }
        require(pin == repeat) { "The two PINs don't match." }
        setPin(vault!!, board!!, pinFile, master, pin)
        notice = "PIN set. Next time, unlock with it while the board is reachable."
        done()
    }

    /** Checks the master password, then the system asks for a fingerprint and the vault key is sealed with it. */
    fun enableFingerprint(ctx: Context, master: String, done: () -> Unit) = run {
        require(vault!!.verifyMasterPassword(master)) { "That master password doesn't open this vault." }
        val id = vault!!.vaultId()!!
        val key = vault!!.keyCopy()
        main.post {
            Biometric.enable(ctx, bioFile, id, key, done = {
                key.fill(0)
                bioOn = true
                notice = "Fingerprint unlock is on."
                done()
            }, failed = {
                key.fill(0)
                if (it.isNotEmpty()) message = "Fingerprint unlock wasn't turned on: $it"
            })
        }
    }

    fun disableFingerprint() {
        Biometric.disable(bioFile)
        bioOn = false
        notice = "Fingerprint unlock is off."
    }

    fun unlockFingerprint(ctx: Context) {
        message = ""
        val id = vault?.vaultId() ?: return
        Biometric.open(ctx, bioFile, id, done = { key ->
            run {
                val ok = vault!!.unlockWithKey(key)
                key.fill(0)
                if (!ok) throw Exception("Fingerprint unlock doesn't open this vault any more. Use the master password.")
                opened()
            }
        }, failed = {
            bioOn = bioFile.exists() // gone if the fingerprints changed
            if (it.isNotEmpty()) message = it
        })
    }

    fun removePin() {
        pinFile.delete()
        notice = "PIN removed. Unlock with the master password."
    }

    /** The board joined another network: same pairing, new address. Re-pairing would also delete the PIN. */
    fun setHost(text: String, close: () -> Unit) {
        val (h, p) = parseHost(text)
        board!!.host = h
        board!!.port = p
        prefs.edit().putString("host", text.trim()).apply()
        close()
        syncNow()
    }

    fun loadStorage() = run {
        storage = try {
            board!!.storage().text().removePrefix("Board storage: ")
        } catch (e: StoreUnavailable) {
            "Unknown while the board is offline"
        }
    }

    fun syncNow() {
        syncing = true
        run {
            vault!!.sync()
            opened()
        }
    }

    fun save(c: Credential) = run {
        vault!!.put(c)
        opened()
    }

    fun delete(platform: String) = run {
        vault!!.remove(platform)
        opened()
        notice = "Deleted $platform."
    }

    fun noteAccess(c: Credential) = worker.execute { vault?.takeIf { it.unlocked }?.noteAccess(c) }

    // Queued behind any running unlock, so a vault opened while going to the background is locked again too
    fun lock() = worker.execute {
        vault?.lock()
        items = emptyList()
        message = ""
        notice = ""
        if (screen == Screen.Vault) screen = Screen.Unlock
    }
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        if (!BuildConfig.DEMO) // no screenshots, no previews in the app switcher
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        App.init(this)
        setContent {
            PwTheme {
                Surface(Modifier.fillMaxSize(), color = palette.enclosure) {
                    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 16.dp)) {
                        when (App.screen) {
                            Screen.Pair -> PairScreen()
                            Screen.Unlock -> UnlockScreen()
                            Screen.Vault -> VaultScreen()
                        }
                    }
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) App.lock() // leaving the app locks it
    }
}

/** Marked sensitive (keyboards don't preview it) and cleared after 30 s. */
private fun copy(ctx: Context, text: String) {
    val cm = ctx.getSystemService(ClipboardManager::class.java)
    cm.setPrimaryClip(ClipData.newPlainText("pwvault", text).apply {
        description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
    })
    Handler(Looper.getMainLooper()).postDelayed({ cm.clearPrimaryClip() }, 30_000)
}

private fun generatePassword(): String {
    val chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%+-.:=?@_"
    val rng = SecureRandom()
    return (1..20).map { chars[rng.nextInt(chars.length)] }.joinToString("")
}

private fun clock(ms: Long) = SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(ms))

// ---- shared pieces ----

/** The status of the board, in the board's own words and font, for the top of the unlock and vault screens. */
private fun boardLine(): String = when {
    !App.hasBoard -> "no board (demo)"
    App.hasVault == null && App.busy -> "reaching board..."
    App.sync == Vault.Sync.Ok -> "synced " + (App.syncedAt?.let(::clock) ?: "")
    App.sync == Vault.Sync.Offline -> "board offline"
    App.sync == Vault.Sync.Error -> "sync failed"
    else -> "board not checked"
}

@Composable
private fun Feedback() {
    if (App.busy && !App.syncing) LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 12.dp), color = palette.accent,
        trackColor = palette.line)
    if (App.message.isNotEmpty())
        Text(App.message, Modifier.padding(top = 12.dp), color = palette.danger, style = MaterialTheme.typography.bodyMedium)
    if (App.notice.isNotEmpty())
        Text(App.notice, Modifier.padding(top = 12.dp), color = palette.muted, style = MaterialTheme.typography.bodyMedium)
}

@Composable
private fun Prose(text: String, modifier: Modifier = Modifier) =
    Text(text, modifier.padding(vertical = 8.dp), color = palette.muted, style = MaterialTheme.typography.bodyMedium)

@Composable
private fun Heading(text: String) =
    Text(text, Modifier.padding(top = 24.dp, bottom = 4.dp), color = palette.ink, style = MaterialTheme.typography.headlineSmall)

// ---- pair ----

@Composable
private fun ColumnScope.PairScreen() {
    val ctx = LocalContext.current
    var host by rememberSaveable { mutableStateOf(App.host) }
    var name by rememberSaveable { mutableStateOf(App.deviceName) }
    var code by rememberSaveable { mutableStateOf("") }
    var typing by rememberSaveable { mutableStateOf(false) }
    val nameOk = validDeviceName(name)

    fun scan() = GmsBarcodeScanning.getClient(ctx, GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build())
        .startScan()
        .addOnSuccessListener { b ->
            val qr = parsePairQr(b.rawValue.orEmpty())
            if (qr == null) App.message = "That's not the board's pairing code. Press BOOT on the board and scan the code it shows."
            else {
                host = qr.first
                code = qr.second
                App.pair(host, name, code)
            }
        }
        .addOnFailureListener { App.message = "The scanner didn't open (${it.message}). Type the code instead." }

    Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) { // the root's safeDrawingPadding already makes room for the keyboard
        Spacer(Modifier.height(16.dp))
        // The OLED shows the steps while waiting, then what to do on the board during the exchange
        if (App.pairing) Oled(listOf(OledText("pairing"), OledText("press BOOT", y = 22, size = 2), OledText("on the board", y = 44),
            OledText("to approve", y = 54)), rules = listOf(10))
        else Oled(listOf(OledText("pair this phone"), OledText("1 press BOOT", y = 18), OledText("2 scan its code", y = 30),
            OledText("3 press BOOT again", y = 42)), rules = listOf(10))
        Heading("Pair with the board")
        Prose("The board shows a code for 2 minutes after you press BOOT. Scan it, then press BOOT again to let this " +
            "phone in.")
        Field(name, { name = it.lowercase().trim() }, "Name for this phone")
        if (!nameOk) Text("Use 1 to 20 lowercase letters, digits or dashes.", color = palette.danger,
            style = MaterialTheme.typography.bodySmall)
        AnimatedVisibility(typing) {
            Column {
                Field(host, { host = it }, "Board address, as shown on its screen")
                Field(code, { code = it }, "Code", caps = true, onDone = { App.pair(host, name, code) })
            }
        }
        Feedback()
    }
    Column(Modifier.navigationBarsPadding().padding(bottom = 8.dp)) {
        if (typing) PrimaryButton("Pair", { App.pair(host, name, code) }, enabled = !App.busy && nameOk && host.isNotBlank())
        else PrimaryButton("Scan the code", { App.message = ""; scan() }, enabled = !App.busy && nameOk)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            QuietButton(if (typing) "Scan instead" else "Type the code instead", { typing = !typing })
            if (App.paired) QuietButton("Cancel", { App.message = ""; App.screen = Screen.Unlock }, color = palette.muted)
        }
    }
}

// ---- unlock ----

private enum class Method { Fingerprint, Pin, Password }

@Composable
private fun ColumnScope.UnlockScreen() {
    LaunchedEffect(Unit) { if (App.hasVault == null) App.check() }
    val ctx = LocalContext.current
    var secret by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    val focus = remember { FocusRequester() }
    // What's set up on this phone, best first. A PIN needs the board; a fingerprint doesn't.
    val methods = listOfNotNull(
        Method.Fingerprint.takeIf { App.bioOn && Biometric.available(ctx) },
        Method.Pin.takeIf { App.hasBoard && App.pinFile.exists() },
        Method.Password,
    )
    var chosen by remember { mutableStateOf<Method?>(null) }
    val method = chosen?.takeIf { it in methods } ?: methods.first()
    val creating = App.hasVault == false && (App.sync == Vault.Sync.Ok || !App.hasBoard)
    val stranded = App.hasVault == false && !creating // no copy here, and the board can't be reached
    val go = {
        when {
            creating -> App.create(secret, repeat)
            method == Method.Fingerprint -> App.unlockFingerprint(ctx)
            method == Method.Pin -> App.unlockPin(secret)
            else -> App.unlock(secret)
        }
        secret = ""
        repeat = ""
    }

    Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) { // the root's safeDrawingPadding already makes room for the keyboard
        Spacer(Modifier.height(16.dp))
        Oled(listOf(OledText("pwvault", x = 22, y = 14, size = 2), OledText(boardLine(), y = 42),
            OledText(if (App.hasBoard) App.host else "local vault", y = 56)))
        when {
            App.hasVault == null -> Prose("Looking for the vault on the board.", Modifier.padding(top = 16.dp))
            stranded -> {
                Heading("Can't reach the board")
                Prose("This phone doesn't have a copy of the vault yet, so it needs the board once. Join the Wi-Fi " +
                    "the board is on and try again.")
                if (App.syncError.isNotEmpty()) Text(App.syncError, color = palette.muted, style = MaterialTheme.typography.bodySmall)
            }
            creating -> {
                Heading("Create your vault")
                Prose("The master password is the only way into the vault. Nobody can reset it, so pick one you won't forget.")
                Field(secret, { secret = it }, "Master password", Modifier.focusRequester(focus), secret = true)
                Field(repeat, { repeat = it }, "Master password again", secret = true, onDone = go)
            }
            method == Method.Fingerprint -> {
                Heading("Unlock")
                Prose("Tap the button below, then touch the fingerprint sensor.")
            }
            else -> {
                Heading(if (method == Method.Pin) "Unlock with your PIN" else "Unlock")
                if (App.sync == Vault.Sync.Offline && App.hasBoard)
                    Prose(if (method == Method.Pin) "A PIN needs the board, which is offline. Use the master password instead."
                        else "The board is offline, so this opens the copy on this phone. It syncs when the board is back.")
                Field(secret, { secret = it }, if (method == Method.Pin) "PIN" else "Master password",
                    Modifier.focusRequester(focus), secret = true, digits = method == Method.Pin, onDone = go)
                LaunchedEffect(method) { runCatching { focus.requestFocus() } }
            }
        }
        Feedback()
    }
    Column(Modifier.navigationBarsPadding().padding(bottom = 8.dp)) {
        when {
            stranded -> PrimaryButton("Try again", { App.check() }, enabled = !App.busy)
            creating -> PrimaryButton("Create vault", go, enabled = !App.busy && secret.isNotEmpty() && repeat.isNotEmpty())
            method == Method.Fingerprint -> PrimaryButton("Unlock with fingerprint", go, enabled = !App.busy)
            App.hasVault == true -> PrimaryButton("Unlock", go, enabled = !App.busy && secret.isNotEmpty())
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Row {
                if (App.hasVault == true) for (m in methods) if (m != method)
                    QuietButton(when (m) {
                        Method.Fingerprint -> "Fingerprint"
                        Method.Pin -> "PIN"
                        Method.Password -> "Master password"
                    }, { chosen = m; secret = ""; App.message = "" })
            }
            if (!BuildConfig.DEMO) QuietButton("Pair again", { App.message = ""; App.screen = Screen.Pair }, color = palette.muted)
        }
    }
}

// ---- vault ----

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ColumnScope.VaultScreen() {
    var query by remember { mutableStateOf("") }
    var open by remember { mutableStateOf<Credential?>(null) }
    var edit by remember { mutableStateOf<Credential?>(null) } // platform "" = a new entry
    var pinSheet by remember { mutableStateOf(false) }
    var bioSheet by remember { mutableStateOf(false) }
    var hostSheet by remember { mutableStateOf(false) }
    var settings by remember { mutableStateOf(false) }
    val shown = App.items.filter { it.platform.contains(query, true) || it.username.contains(query, true) }
    val count = App.items.size

    Spacer(Modifier.height(12.dp))
    // One line of the board's screen: how the vault stands, and how big it is
    Oled(listOf(OledText(if (App.syncing) "syncing..." else boardLine(), y = 2),
        OledText(if (count == 1) "1 entry" else "$count entries", y = 2, right = true)), rows = 11)
    if (App.sync == Vault.Sync.Error && App.syncError.isNotEmpty())
        Text(App.syncError, Modifier.padding(top = 8.dp), color = palette.danger, style = MaterialTheme.typography.bodySmall,
            maxLines = 3, overflow = TextOverflow.Ellipsis)
    App.update?.let { r -> UpdateBanner(r) }
    if (count > 0) Field(query, { query = it }, "Search", Modifier.padding(top = 8.dp))
    Feedback()

    PullToRefreshBox(App.syncing, { App.syncNow() }, Modifier.weight(1f).padding(top = 8.dp)) {
        LazyColumn(Modifier.fillMaxSize()) {
            if (count == 0) item {
                Heading("No entries yet")
                Prose("Add the first one with the button below. It's saved on this phone and on the board.")
            } else if (shown.isEmpty()) item {
                Prose("Nothing matches “$query”.", Modifier.padding(top = 16.dp))
            }
            if (shown.isNotEmpty()) item {
                // One quiet block, like the desktop's list: rows separated by 1 px lines
                Column(Modifier.clip(RoundedCornerShape(6.dp)).background(palette.surface).border(1.dp, palette.line, RoundedCornerShape(6.dp))) {
                    shown.forEachIndexed { i, c ->
                        if (i > 0) HorizontalDivider(color = palette.line)
                        Column(Modifier.fillMaxWidth().clickable { open = c; App.noteAccess(c) }
                            .padding(horizontal = 16.dp, vertical = 12.dp)) {
                            Text(c.platform, color = palette.ink, style = MaterialTheme.typography.titleMedium, maxLines = 1,
                                overflow = TextOverflow.Ellipsis)
                            Text(c.username, color = palette.muted, style = MaterialTheme.typography.bodyMedium, maxLines = 1,
                                overflow = TextOverflow.Ellipsis)
                        }
                    }
                }
                Spacer(Modifier.height(12.dp))
            }
        }
    }

    Row(Modifier.fillMaxWidth().navigationBarsPadding().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        QuietButton("Lock", { App.lock() }, color = palette.muted)
        QuietButton("Settings", { settings = true }, color = palette.muted)
        Spacer(Modifier.width(8.dp))
        PrimaryButton("Add entry", { edit = Credential("", "", "") }, enabled = !App.busy, modifier = Modifier.weight(1f))
    }

    open?.let { c -> EntrySheet(c, close = { open = null }, edit = { open = null; edit = c }) }
    edit?.let { EditSheet(it) { edit = null } }
    if (pinSheet) PinSheet { pinSheet = false }
    if (bioSheet) FingerprintSheet { bioSheet = false }
    if (hostSheet) HostSheet { hostSheet = false }
    // One sheet at a time: a setting that needs its own sheet closes Settings first
    if (settings) SettingsSheet(close = { settings = false }, pin = { settings = false; pinSheet = true },
        fingerprint = { settings = false; bioSheet = true }, host = { settings = false; hostSheet = true })
}

/**
 * Everything that isn't an entry, grouped by what it acts on: this phone, the board, the app. Each row says what
 * the setting is now, and its button says what tapping does.
 */
@Composable
private fun SettingsSheet(close: () -> Unit, pin: () -> Unit, fingerprint: () -> Unit, host: () -> Unit) {
    val ctx = LocalContext.current
    LaunchedEffect(Unit) { if (App.hasBoard) App.loadStorage() }
    Sheet(close) { Column(Modifier.verticalScroll(rememberScrollState())) { // taller than a small phone
        Text("Settings", color = palette.ink, style = MaterialTheme.typography.headlineSmall)

        Group("This phone")
        Setting("Name", App.deviceName)
        if (App.hasBoard) Setting("PIN unlock", if (App.pinFile.exists()) "On, while the board is reachable" else "Off") {
            QuietButton(if (App.pinFile.exists()) "Change" else "Set up", pin)
        }
        if (App.bioOn || Biometric.available(ctx)) Setting("Fingerprint unlock", if (App.bioOn) "On" else "Off") {
            Switch(App.bioOn, { if (App.bioOn) App.disableFingerprint() else fingerprint() },
                colors = SwitchDefaults.colors(checkedTrackColor = palette.accent, checkedThumbColor = palette.onAccent))
        }

        if (App.hasBoard) {
            Group("Board")
            Setting("Sync", boardLine().replaceFirstChar { it.uppercase() }) {
                QuietButton("Sync now", { App.syncNow() }, enabled = !App.busy)
            }
            Setting("Storage", App.storage.ifEmpty { "Checking..." })
            Setting("Address", App.host) { QuietButton("Change", host) }
            Setting("Pairing", "Paired as ${App.deviceName}") {
                QuietButton("Pair again", { close(); App.message = ""; App.screen = Screen.Pair }, color = palette.muted)
            }
        }

        if (!BuildConfig.DEMO) {
            Group("App")
            Setting("Version", BuildConfig.VERSION_NAME) {
                QuietButton("Check for updates", { App.checkUpdate(manual = true) })
            }
        }
        Feedback()
    } }
}

@Composable
private fun Group(title: String) {
    Text(title, Modifier.padding(top = 24.dp, bottom = 4.dp), color = palette.accent,
        style = MaterialTheme.typography.titleMedium)
    HorizontalDivider(color = palette.line)
}

/** One setting: its name, what it is now, and at most one action. */
@Composable
private fun Setting(name: String, value: String, action: (@Composable () -> Unit)? = null) {
    Row(Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(name, color = palette.ink, style = MaterialTheme.typography.bodyLarge)
            Text(value, color = palette.muted, style = MaterialTheme.typography.bodySmall, maxLines = 2,
                overflow = TextOverflow.Ellipsis)
        }
        action?.invoke()
    }
    HorizontalDivider(color = palette.line)
}

@Composable
private fun HostSheet(close: () -> Unit) {
    var host by remember { mutableStateOf(App.host) }
    val go = { if (host.isNotBlank()) App.setHost(host, close) }
    Sheet(close) {
        Text("Board address", color = palette.ink, style = MaterialTheme.typography.headlineSmall)
        Prose("If the board joined another network, type the IP its screen shows now. The pairing and PIN stay.")
        Field(host, { host = it }, "Board address", onDone = go)
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            QuietButton("Cancel", close, color = palette.muted)
            Spacer(Modifier.width(8.dp))
            PrimaryButton("Save", go, enabled = !App.busy && host.isNotBlank(), modifier = Modifier.weight(1f))
        }
        Feedback()
    }
}

@Composable
private fun UpdateBanner(r: Release) {
    val ctx = LocalContext.current
    Row(Modifier.fillMaxWidth().padding(top = 8.dp).clip(RoundedCornerShape(6.dp)).background(palette.surface)
        .border(1.dp, palette.line, RoundedCornerShape(6.dp)).padding(start = 16.dp),
        verticalAlignment = Alignment.CenterVertically) {
        val p = App.updating
        Text(if (p == null) "pwvault ${r.version.trimStart('v')} is available." else "Downloading the update, $p%",
            Modifier.weight(1f), color = palette.ink, style = MaterialTheme.typography.bodyMedium)
        QuietButton("Update", { App.installUpdate(ctx) }, enabled = p == null)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Sheet(close: () -> Unit, content: @Composable ColumnScope.() -> Unit) =
    ModalBottomSheet(close, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = palette.surface, shape = RoundedCornerShape(topStart = 14.dp, topEnd = 14.dp)) {
        Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 16.dp).navigationBarsPadding().imePadding(), content = content)
    }

/** A value with its own actions; "Copy" answers with "Copied" for a moment. */
@Composable
private fun ValueRow(label: String, value: String, secret: Boolean = false) {
    val ctx = LocalContext.current
    var show by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }
    LaunchedEffect(copied) { if (copied) { delay(1500); copied = false } }
    Text(label, Modifier.padding(top = 16.dp), color = palette.muted, style = MaterialTheme.typography.bodySmall)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(if (secret && !show) "•".repeat(12) else value, Modifier.weight(1f),
            color = palette.ink, style = if (secret) Mono else MaterialTheme.typography.bodyLarge)
        if (secret) QuietButton(if (show) "Hide" else "Show", { show = !show }, color = palette.muted)
        QuietButton(if (copied) "Copied" else "Copy", { copy(ctx, value); copied = true })
    }
}

@Composable
private fun EntrySheet(c: Credential, close: () -> Unit, edit: () -> Unit) {
    var confirm by remember { mutableStateOf(false) }
    Sheet(close) {
        Text(c.platform, color = palette.ink, style = MaterialTheme.typography.headlineSmall)
        ValueRow("Username", c.username)
        ValueRow("Password", c.password, secret = true)
        Text("Copied values are cleared from the clipboard after 30 seconds.", Modifier.padding(top = 12.dp),
            color = palette.muted, style = MaterialTheme.typography.bodySmall)
        HorizontalDivider(Modifier.padding(vertical = 16.dp), color = palette.line)
        if (confirm) {
            Text("Delete ${c.platform}? It's removed from the board and every device on their next sync.",
                color = palette.ink, style = MaterialTheme.typography.bodyMedium)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                QuietButton("Keep it", { confirm = false }, color = palette.muted)
                QuietButton("Delete", { App.delete(c.platform); close() }, color = palette.danger)
            }
        } else Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            QuietButton("Delete", { confirm = true }, color = palette.danger)
            QuietButton("Edit", edit)
        }
    }
}

@Composable
private fun EditSheet(c: Credential, close: () -> Unit) {
    val isNew = c.platform.isEmpty()
    var platform by remember { mutableStateOf(c.platform) }
    var username by remember { mutableStateOf(c.username) }
    var password by remember { mutableStateOf(c.password) }
    val show = remember { mutableStateOf(false) } // hidden until asked, or until a password is generated
    // PROTOCOL.md §4: one account per platform, so adding an existing platform replaces it
    val replaces = isNew && App.items.any { it.platform.equals(platform.trim(), ignoreCase = true) }
    val ready = platform.isNotBlank() && username.isNotEmpty() && password.isNotEmpty()
    val save = { if (ready) { App.save(Credential(platform.trim(), username, password, c.alg)); close() } }
    Sheet(close) {
        Text(if (isNew) "New entry" else "Edit ${c.platform}", color = palette.ink, style = MaterialTheme.typography.headlineSmall)
        if (isNew) Field(platform, { platform = it }, "Site or app", Modifier.padding(top = 8.dp))
        if (replaces) Text("You already have ${platform.trim()}. Saving replaces it: the vault keeps one account per site.",
            color = palette.danger, style = MaterialTheme.typography.bodySmall)
        Field(username, { username = it }, "Username or email")
        Field(password, { password = it }, "Password", secret = true, onDone = save, visible = show)
        QuietButton("Generate a strong password", { password = generatePassword(); show.value = true })
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            QuietButton("Cancel", close, color = palette.muted)
            Spacer(Modifier.width(8.dp))
            PrimaryButton(if (isNew) "Add entry" else "Save changes", save, enabled = ready, modifier = Modifier.weight(1f))
        }
    }
}

@Composable
private fun PinSheet(close: () -> Unit) {
    var master by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    val has = App.pinFile.exists()
    Sheet(close) {
        Text(if (has) "Change your PIN" else "Set a PIN", color = palette.ink, style = MaterialTheme.typography.headlineSmall)
        Prose("A PIN unlocks this phone while the board is reachable. After 5 wrong tries the board deletes it, and " +
            "you unlock with the master password again.")
        Field(master, { master = it }, "Master password", secret = true)
        Field(pin, { pin = it }, "New PIN, 4 to 32 digits", secret = true, digits = true)
        Field(repeat, { repeat = it }, "New PIN again", secret = true, digits = true,
            onDone = { App.setPin(master, pin, repeat, close) })
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            if (has) QuietButton("Remove PIN", { App.removePin(); close() }, color = palette.danger)
            else QuietButton("Cancel", close, color = palette.muted)
            Spacer(Modifier.width(8.dp))
            PrimaryButton("Save PIN", { App.setPin(master, pin, repeat, close) },
                enabled = !App.busy && master.isNotEmpty() && pin.isNotEmpty(), modifier = Modifier.weight(1f))
        }
        Feedback()
    }
}

@Composable
private fun FingerprintSheet(close: () -> Unit) {
    val ctx = LocalContext.current
    var master by remember { mutableStateOf("") }
    val go = { App.enableFingerprint(ctx, master, close) }
    Sheet(close) {
        Text("Turn on fingerprint unlock", color = palette.ink, style = MaterialTheme.typography.headlineSmall)
        Prose("Unlock this phone's vault with a fingerprint, even away from the board. If anyone adds a fingerprint to " +
            "this phone, it turns itself off and asks for the master password again.")
        Field(master, { master = it }, "Master password", secret = true, onDone = go)
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            QuietButton("Cancel", close, color = palette.muted)
            Spacer(Modifier.width(8.dp))
            PrimaryButton("Continue", go, enabled = !App.busy && master.isNotEmpty(), modifier = Modifier.weight(1f))
        }
        Feedback()
    }
}
