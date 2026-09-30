package dev.pwvault

// Updates from the project's GitHub releases, like the desktop's AppUpdater: the latest release's tag is its version,
// and its `.apk` asset is the Android build. The APK streams straight into Android's package installer, which asks
// the user to confirm and installs it only if it's signed with the same key as this app: a swapped release asset
// can't replace the app.

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.net.Uri
import android.provider.Settings
import org.json.JSONObject
import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection

class Release(val version: String, val apkUrl: String?, val size: Long)

/** Is [tag] ("v2.1", "2.1.3") a later version than [current]? Missing parts count as 0; anything else is ignored. */
fun isNewerVersion(tag: String, current: String): Boolean {
    fun parts(v: String) = v.trimStart('v', 'V').split('.').map { it.takeWhile(Char::isDigit).toIntOrNull() ?: 0 }
    val a = parts(tag)
    val b = parts(current)
    for (i in 0 until maxOf(a.size, b.size)) {
        val x = a.getOrElse(i) { 0 }
        val y = b.getOrElse(i) { 0 }
        if (x != y) return x > y
    }
    return false
}

object Updater {
    /** The latest release. Throws IOException when GitHub can't be reached. */
    fun latest(): Release {
        val c = URL("https://api.github.com/repos/${BuildConfig.UPDATE_REPO}/releases/latest").openConnection()
            as HttpsURLConnection
        c.setRequestProperty("Accept", "application/vnd.github+json")
        c.connectTimeout = 5000
        c.readTimeout = 10_000
        if (c.responseCode != 200) throw IOException("GitHub answered HTTP ${c.responseCode}")
        val j = JSONObject(c.inputStream.use { String(it.readBytes()) })
        val assets = j.optJSONArray("assets")
        val apk = (0 until (assets?.length() ?: 0)).map { assets!!.getJSONObject(it) }
            .firstOrNull { it.getString("name").endsWith(".apk") }
        return Release(j.getString("tag_name"), apk?.getString("browser_download_url"), apk?.optLong("size") ?: -1)
    }

    /** Whether Android lets this app install packages; if not, [allowIntent] opens the switch for it. */
    fun canInstall(ctx: Context) = ctx.packageManager.canRequestPackageInstalls()

    fun allowIntent(ctx: Context) =
        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /** Downloads [r]'s APK into an install session and commits it; Android then asks the user to confirm. */
    fun install(ctx: Context, r: Release, progress: (Int) -> Unit) {
        val installer = ctx.packageManager.packageInstaller
        val id = installer.createSession(PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL))
        installer.openSession(id).use { session ->
            val c = URL(r.apkUrl).openConnection() as HttpsURLConnection // GitHub redirects to its file host
            c.connectTimeout = 5000
            c.readTimeout = 30_000
            if (c.responseCode != 200) throw IOException("the download answered HTTP ${c.responseCode}")
            val total = c.contentLengthLong.takeIf { it > 0 } ?: r.size
            c.inputStream.use { input ->
                session.openWrite("pwvault.apk", 0, total).use { out ->
                    val buf = ByteArray(64 * 1024)
                    var done = 0L
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        done += n
                        if (total > 0) progress((done * 100 / total).toInt())
                    }
                    session.fsync(out)
                }
            }
            val status = PendingIntent.getBroadcast(ctx, id, Intent(ctx, InstallReceiver::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE) // the installer fills in the result
            session.commit(status.intentSender)
        }
    }
}

/** The install session's outcome: bring up Android's confirmation, or report why it failed. */
class InstallReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION") // the typed overload is API 33+
                val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
                ctx.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
            PackageInstaller.STATUS_SUCCESS -> Unit // the app restarts as the new version
            PackageInstaller.STATUS_FAILURE_ABORTED -> App.notice = "Update cancelled."
            PackageInstaller.STATUS_FAILURE_CONFLICT, PackageInstaller.STATUS_FAILURE_INCOMPATIBLE ->
                App.message = "The update isn't signed like this app, so Android refused it. Install it by hand once " +
                    "(uninstall first), then updates work from here."
            else -> App.message = "The update didn't install: " +
                intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE).orEmpty()
        }
        App.updating = null
    }
}
