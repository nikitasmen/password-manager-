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
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Executors

private const val PAIR_PORT = 8444 // PROTOCOL.md §9

enum class Screen { Pair, Unlock, Vault }

/**
 * App state lives here, not in the activity, so a rotation keeps it. Every vault call runs on one worker thread, in
 * order. Files (filesDir): vault.json, sync.json, pin.json, server.der (the pinned board cert), device.der; the
 * device key is in the Android Keystore and never leaves it.
 */
object App {
    private lateinit var dir: File
    private lateinit var prefs: SharedPreferences
    private var vault: Vault? = null
    private var board: EspStore? = null
    private val worker = Executors.newSingleThreadExecutor()
    val pinFile get() = File(dir, "pin.json")
    val host get() = prefs.getString("host", "").orEmpty()
    val paired get() = vault != null

    var screen by mutableStateOf(Screen.Pair)
    var hasVault by mutableStateOf<Boolean?>(null) // null = not checked yet
    var reachable by mutableStateOf(false)
    var busy by mutableStateOf(false)
    var message by mutableStateOf("")
    var status by mutableStateOf("")
    var items by mutableStateOf(listOf<Credential>())

    fun init(ctx: Context) {
        if (::dir.isInitialized) return
        dir = ctx.filesDir
        prefs = ctx.getSharedPreferences("pwvault", Context.MODE_PRIVATE)
        load()
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
        worker.execute {
            try {
                task()
            } catch (e: Exception) {
                message = e.message ?: e.toString()
            } finally {
                busy = false
            }
        }
    }

    private fun showStatus() {
        val v = vault ?: return
        reachable = v.status == Vault.Sync.Ok
        status = when (v.status) {
            Vault.Sync.Ok -> "Synced with the board"
            Vault.Sync.Offline -> "Using this phone's copy. ${v.error}"
            Vault.Sync.Error -> "Sync failed: ${v.error}"
            Vault.Sync.Disabled -> ""
        }
    }

    private fun opened() {
        items = vault!!.credentials()
        showStatus()
        screen = Screen.Vault
    }

    fun check() = run {
        val exists = vault!!.exists()
        showStatus()
        hasVault = exists
    }

    fun pair(hostText: String, name: String, typed: String) = run {
        val code = normalizePairCode(typed)
        if (code.isEmpty()) throw PairError("The code on the board's screen has 16 characters.")
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
        prefs.edit().putString("host", hostText.trim()).putString("alias", alias).commit()
        pinFile.delete() // re-pairing deleted this name's PIN on the board
        load()
    }

    fun create(password: String, repeat: String) = run {
        require(password.isNotEmpty() && password == repeat) { "The passwords are empty or don't match." }
        vault!!.create(password)
        opened()
    }

    fun unlock(password: String) = run {
        if (!vault!!.unlock(password)) throw Exception("Wrong master password.")
        opened()
    }

    fun unlockPin(pin: String) = run {
        when (val r = unlockWithPin(vault!!, board!!, pinFile, pin)) {
            PinResult.Unlocked -> opened()
            is PinResult.Wrong -> message = "Wrong PIN: ${r.left} tries left."
            PinResult.Removed -> message = "The PIN was removed (too many tries, or re-paired). Use the master password."
            is PinResult.Failed -> message = r.why
        }
    }

    fun setPin(master: String, pin: String, repeat: String) = run {
        require(pin == repeat) { "The two PINs don't match." }
        setPin(vault!!, board!!, pinFile, master, pin)
        message = "PIN set."
    }

    fun removePin() = pinFile.delete()

    fun sync() = run {
        vault!!.sync()
        opened()
    }

    fun save(c: Credential) = run {
        vault!!.put(c)
        opened()
    }

    fun delete(platform: String) = run {
        vault!!.remove(platform)
        opened()
    }

    fun noteAccess(c: Credential) = worker.execute { vault?.takeIf { it.unlocked }?.noteAccess(c) }

    // Queued behind any running unlock, so a vault opened while going to the background is locked again too
    fun lock() = worker.execute {
        vault?.lock()
        items = emptyList()
        if (screen == Screen.Vault) screen = Screen.Unlock
    }
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE) // no screenshots
        App.init(this)
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                Surface(Modifier.fillMaxSize()) {
                    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(16.dp)) {
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

@Composable
private fun Field(value: String, onChange: (String) -> Unit, label: String, enabled: Boolean = true, caps: Boolean = false) =
    OutlinedTextField(
        value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp), enabled = enabled, singleLine = true,
        label = { Text(label) },
        keyboardOptions = KeyboardOptions(
            capitalization = if (caps) KeyboardCapitalization.Characters else KeyboardCapitalization.None,
            autoCorrectEnabled = false,
        ),
    )

@Composable
private fun Secret(value: String, onChange: (String) -> Unit, label: String, digits: Boolean = false, shown: Boolean = false) =
    OutlinedTextField(
        value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp), singleLine = true, label = { Text(label) },
        visualTransformation = if (shown) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(
            keyboardType = if (digits) KeyboardType.NumberPassword else KeyboardType.Password, autoCorrectEnabled = false,
        ),
    )

@Composable
private fun Feedback() {
    if (App.busy) LinearProgressIndicator(Modifier.fillMaxWidth().padding(vertical = 8.dp))
    if (App.message.isNotEmpty())
        Text(App.message, Modifier.padding(vertical = 8.dp), color = MaterialTheme.colorScheme.error)
}

@Composable
private fun Title(text: String) = Text(text, Modifier.padding(bottom = 8.dp), style = MaterialTheme.typography.headlineSmall)

@Composable
private fun ColumnScope.PairScreen() {
    val ctx = LocalContext.current
    var host by rememberSaveable { mutableStateOf(App.host) }
    var name by rememberSaveable { mutableStateOf("phone") }
    var code by rememberSaveable { mutableStateOf("") }
    fun scan() = GmsBarcodeScanning.getClient(ctx, GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build())
        .startScan()
        .addOnSuccessListener { b ->
            val qr = parsePairQr(b.rawValue.orEmpty())
            if (qr == null) App.message = "That isn't the board's pairing QR code."
            else {
                host = qr.first
                code = qr.second
                App.pair(host, name, code) // the board then asks for the approving BOOT press
            }
        }
        .addOnFailureListener { App.message = "Couldn't scan: ${it.message}" }
    Title("Pair with the board")
    Text("Press BOOT on the board: it shows a QR code and a 16-character code for 2 minutes. Scan it, or type the " +
        "address and code and tap Pair. Then press BOOT again to approve.")
    Button({ App.message = ""; scan() }, Modifier.fillMaxWidth().padding(vertical = 8.dp), enabled = !App.busy) {
        Text("Scan the QR code")
    }
    Field(host, { host = it }, "Board address (IP, or IP:port)")
    Field(name, { name = it.lowercase() }, "Name for this phone")
    Field(code, { code = it }, "Code from the board's screen", caps = true)
    Button({ App.pair(host, name, code) }, Modifier.fillMaxWidth(), enabled = !App.busy && host.isNotBlank()) {
        Text("Pair")
    }
    if (App.paired) TextButton({ App.message = ""; App.screen = Screen.Unlock }) { Text("Cancel") }
    Feedback()
}

@Composable
private fun ColumnScope.UnlockScreen() {
    LaunchedEffect(Unit) { if (App.hasVault == null) App.check() }
    var secret by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    var usePin by remember { mutableStateOf(true) }
    val ready = !App.busy && secret.isNotEmpty()
    Title("pwvault")
    if (App.status.isNotEmpty()) Text(App.status, style = MaterialTheme.typography.bodySmall)
    when {
        App.hasVault == null -> Text("Connecting to the board…")
        App.hasVault == false && !App.reachable -> {
            Text("There's no vault on this phone yet, and the board can't be reached. Join the board's Wi-Fi.")
            Button({ App.check() }, enabled = !App.busy) { Text("Retry") }
        }
        App.hasVault == false -> {
            Text("The board has no vault yet. Create one:")
            Secret(secret, { secret = it }, "Master password")
            Secret(repeat, { repeat = it }, "Repeat it")
            Button({ App.create(secret, repeat) }, Modifier.fillMaxWidth(), enabled = ready) { Text("Create vault") }
        }
        usePin && App.pinFile.exists() -> {
            Secret(secret, { secret = it }, "PIN", digits = true)
            Button({ App.unlockPin(secret); secret = "" }, Modifier.fillMaxWidth(), enabled = ready) { Text("Unlock") }
            TextButton({ usePin = false; secret = "" }) { Text("Use the master password") }
        }
        else -> {
            Secret(secret, { secret = it }, "Master password")
            Button({ App.unlock(secret); secret = "" }, Modifier.fillMaxWidth(), enabled = ready) { Text("Unlock") }
            if (App.pinFile.exists()) TextButton({ usePin = true; secret = "" }) { Text("Use the PIN") }
        }
    }
    Feedback()
    TextButton({ App.message = ""; App.screen = Screen.Pair }) { Text("Pair again") }
}

@Composable
private fun ColumnScope.VaultScreen() {
    var query by remember { mutableStateOf("") }
    var open by remember { mutableStateOf<Credential?>(null) }
    var edit by remember { mutableStateOf<Credential?>(null) } // platform "" = a new entry
    var pinDialog by remember { mutableStateOf(false) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("pwvault", Modifier.weight(1f), style = MaterialTheme.typography.headlineSmall)
        TextButton({ App.sync() }, enabled = !App.busy) { Text("Sync") }
        TextButton({ pinDialog = true }) { Text("PIN") }
        TextButton({ App.lock() }) { Text("Lock") }
    }
    Text(App.status, style = MaterialTheme.typography.bodySmall)
    Feedback()
    Field(query, { query = it }, "Search")
    val shown = App.items.filter { it.platform.contains(query, true) || it.username.contains(query, true) }
    LazyColumn(Modifier.weight(1f)) {
        items(shown, key = { it.platform.lowercase() }) { c ->
            ListItem(
                headlineContent = { Text(c.platform) }, supportingContent = { Text(c.username) },
                modifier = Modifier.clickable { open = c; App.noteAccess(c) },
            )
            HorizontalDivider()
        }
    }
    Button({ edit = Credential("", "", "") }, Modifier.fillMaxWidth(), enabled = !App.busy) { Text("Add") }

    open?.let { c -> DetailDialog(c, close = { open = null }, edit = { open = null; edit = c }) }
    edit?.let { EditDialog(it) { edit = null } }
    if (pinDialog) PinDialog { pinDialog = false }
}

@Composable
private fun DetailDialog(c: Credential, close: () -> Unit, edit: () -> Unit) {
    val ctx = LocalContext.current
    var show by remember { mutableStateOf(false) }
    var confirm by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = close,
        title = { Text(c.platform) },
        text = {
            Column {
                Text("Username", style = MaterialTheme.typography.labelMedium)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(c.username, Modifier.weight(1f))
                    TextButton({ copy(ctx, c.username) }) { Text("Copy") }
                }
                Text("Password", style = MaterialTheme.typography.labelMedium)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(if (show) c.password else "••••••••", Modifier.weight(1f), fontFamily = FontFamily.Monospace)
                    TextButton({ show = !show }) { Text(if (show) "Hide" else "Show") }
                    TextButton({ copy(ctx, c.password) }) { Text("Copy") }
                }
            }
        },
        confirmButton = { TextButton(edit) { Text("Edit") } },
        dismissButton = {
            TextButton({ if (confirm) { App.delete(c.platform); close() } else confirm = true }) {
                Text(if (confirm) "Really delete" else "Delete", color = MaterialTheme.colorScheme.error)
            }
        },
    )
}

@Composable
private fun EditDialog(c: Credential, close: () -> Unit) {
    val isNew = c.platform.isEmpty()
    var platform by remember { mutableStateOf(c.platform) }
    var username by remember { mutableStateOf(c.username) }
    var password by remember { mutableStateOf(c.password) }
    var show by remember { mutableStateOf(false) }
    // PROTOCOL.md §4: one account per platform, so adding an existing platform replaces it
    val replaces = isNew && App.items.any { it.platform.equals(platform.trim(), ignoreCase = true) }
    AlertDialog(
        onDismissRequest = close,
        title = { Text(if (isNew) "Add" else "Edit") },
        text = {
            Column {
                Field(platform, { platform = it }, "Platform", enabled = isNew)
                if (replaces) Text("This replaces the existing ${platform.trim()} entry.", color = MaterialTheme.colorScheme.error)
                Field(username, { username = it }, "Username")
                Secret(password, { password = it }, "Password", shown = show)
                Row {
                    TextButton({ show = !show }) { Text(if (show) "Hide" else "Show") }
                    TextButton({ password = generatePassword(); show = true }) { Text("Generate") }
                }
            }
        },
        confirmButton = {
            TextButton(
                { App.save(Credential(platform.trim(), username, password, c.alg)); close() },
                enabled = platform.isNotBlank() && username.isNotEmpty() && password.isNotEmpty(),
            ) { Text("Save") }
        },
        dismissButton = { TextButton(close) { Text("Cancel") } },
    )
}

@Composable
private fun PinDialog(close: () -> Unit) {
    var master by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    val has = App.pinFile.exists()
    AlertDialog(
        onDismissRequest = close,
        title = { Text(if (has) "Change the PIN" else "Set a PIN") },
        text = {
            Column {
                Text("A PIN unlocks this phone only while the board is reachable. 5 wrong tries delete it.")
                Secret(master, { master = it }, "Master password")
                Secret(pin, { pin = it }, "New PIN (4-32 digits)", digits = true)
                Secret(repeat, { repeat = it }, "Repeat the PIN", digits = true)
            }
        },
        confirmButton = { TextButton({ App.setPin(master, pin, repeat); close() }, enabled = master.isNotEmpty()) { Text("Save") } },
        dismissButton = {
            Row {
                if (has) TextButton({ App.removePin(); close() }) { Text("Remove PIN") }
                TextButton(close) { Text("Cancel") }
            }
        },
    )
}
