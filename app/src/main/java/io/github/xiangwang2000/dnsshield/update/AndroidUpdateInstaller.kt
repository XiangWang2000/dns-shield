package io.github.xiangwang2000.dnsshield.update

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.provider.Settings
import android.util.Log
import androidx.core.net.toUri
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

internal enum class InstallOutcome { Installed, Cancelled, Failed }

internal class AndroidUpdateInstaller(context: Context) {
    private val appContext = context.applicationContext
    private val packageManager = appContext.packageManager
    private val packageName = appContext.packageName

    @Suppress("DEPRECATION")
    private val signingFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        // Older archive parsers only collect certificates when GET_SIGNATURES is present.
        PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_SIGNATURES
    } else {
        PackageManager.GET_SIGNATURES
    }

    fun canInstall(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.O || packageManager.canRequestPackageInstalls()

    fun permissionIntent(): Intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES).setData("package:$packageName".toUri())
    } else {
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).setData("package:$packageName".toUri())
    }

    suspend fun install(
        apk: File,
        expectedVersionName: String,
        requestConfirmation: suspend (Intent) -> Unit,
    ): InstallOutcome {
        if (!canInstall()) return InstallOutcome.Failed

        val installer = packageManager.packageInstaller
        var sessionId = -1
        var route: InstallStatusRoute? = null
        var terminalStatusReceived = false

        try {
            val prepared = withContext(Dispatchers.IO) {
                if (!apk.isFile || !apk.canRead() || apk.length() <= 0L ||
                    !isValidUpdate(apk, expectedVersionName)
                ) {
                    return@withContext false
                }

                val size = apk.length()
                val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
                params.setAppPackageName(packageName)
                params.setSize(size)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
                }

                sessionId = installer.createSession(params)
                val nonce = UUID.randomUUID().toString()
                val action = "$packageName.update.INSTALL_STATUS"
                route = InstallStatusRegistry.register(nonce, action, sessionId)
                val statusIntent = Intent(action)
                    .setClass(appContext, AndroidUpdateStatusReceiver::class.java)
                    .setPackage(packageName)
                    .setData("dnsshield-install://$nonce".toUri())
                    .putExtra(AndroidUpdateStatusReceiver.EXTRA_NONCE, nonce)
                var pendingIntentFlags = PendingIntent.FLAG_UPDATE_CURRENT
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    pendingIntentFlags = pendingIntentFlags or PendingIntent.FLAG_MUTABLE
                }
                val statusPendingIntent = PendingIntent.getBroadcast(
                    appContext,
                    nonce.hashCode(),
                    statusIntent,
                    pendingIntentFlags,
                )

                val session = installer.openSession(sessionId)
                try {
                    session.openWrite("base.apk", 0L, size).use { output ->
                        FileInputStream(apk).use { input ->
                            if (input.copyTo(output) != size) throw IllegalStateException("APK size changed")
                        }
                        session.fsync(output)
                    }
                    // The session now owns its copy, and a successful update can stop this process.
                    apk.delete()
                    session.commit(statusPendingIntent.intentSender)
                } finally {
                    session.close()
                }
                true
            }
            if (!prepared) return InstallOutcome.Failed

            val activeRoute = route ?: return InstallOutcome.Failed
            val requestedUserActions = mutableListOf<Intent>()
            return withTimeoutOrNull(INSTALL_SESSION_TIMEOUT_MILLIS) {
                var outcome: InstallOutcome? = null
                while (outcome == null) {
                    val event = activeRoute.events.receiveCatching().getOrNull()
                    if (event == null) {
                        outcome = InstallOutcome.Failed
                        continue
                    }
                    when (event.status) {
                        PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                            val intent = event.userActionIntent
                            if (intent == null) {
                                outcome = InstallOutcome.Failed
                            } else {
                                val intentKey = Intent(intent)
                                if (requestedUserActions.none { it.filterEquals(intentKey) }) {
                                    requestedUserActions += intentKey
                                    requestConfirmation(Intent(intent))
                                }
                            }
                        }
                        PackageInstaller.STATUS_SUCCESS -> {
                            terminalStatusReceived = true
                            outcome = InstallOutcome.Installed
                        }
                        PackageInstaller.STATUS_FAILURE_ABORTED -> {
                            terminalStatusReceived = true
                            outcome = InstallOutcome.Cancelled
                        }
                        else -> {
                            terminalStatusReceived = true
                            outcome = InstallOutcome.Failed
                        }
                    }
                }
                outcome
            } ?: InstallOutcome.Failed
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            Log.w("AppUpdate", "Package install failed: " + failure.javaClass.simpleName)
            return InstallOutcome.Failed
        } finally {
            route?.let(InstallStatusRegistry::unregister)
            if (sessionId >= 0 && !terminalStatusReceived) {
                runCatching { installer.abandonSession(sessionId) }
            }
        }
    }

    private fun isValidUpdate(apk: File, expectedVersionName: String): Boolean {
        val installed = getInstalledPackageInfo() ?: return false
        val archive = readUpdateArchive(apk.absolutePath) ?: return false
        if (archive.packageName != packageName || archive.versionName != expectedVersionName) return false
        if (archive.longVersionCodeCompat() <= installed.longVersionCodeCompat()) return false
        return hasTrustedSigners(installed, archive)
    }

    @Suppress("DEPRECATION")
    private fun getInstalledPackageInfo(): PackageInfo? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(signingFlags.toLong()))
        } else {
            packageManager.getPackageInfo(packageName, signingFlags)
        }
    }.getOrNull()

    @Suppress("DEPRECATION")
    internal fun readUpdateArchive(path: String): PackageInfo? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageArchiveInfo(path, PackageManager.PackageInfoFlags.of(signingFlags.toLong()))
        } else {
            packageManager.getPackageArchiveInfo(path, signingFlags)
        }
    }.getOrNull()

    @Suppress("DEPRECATION")
    private fun PackageInfo.longVersionCodeCompat(): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) longVersionCode else versionCode.toLong()

    @Suppress("DEPRECATION")
    private fun hasTrustedSigners(installed: PackageInfo, archive: PackageInfo): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val installedInfo = installed.signingInfo ?: return false
            val archiveInfo = archive.signingInfo ?: return false
            val installedSigners = signerDigests(installedInfo.apkContentsSigners)
            val archiveSigners = signerDigests(archiveInfo.apkContentsSigners)
            return installedSigners.isNotEmpty() && archiveSigners == installedSigners
        }

        val installedSigners = installed.signatures?.takeIf { it.isNotEmpty() } ?: return false
        val archiveSigners = archive.signatures ?: return false
        return signerDigests(installedSigners) == signerDigests(archiveSigners)
    }

    private fun signerDigests(signatures: Array<Signature>): Set<String> = signatures.mapTo(mutableSetOf()) {
        MessageDigest.getInstance("SHA-256").digest(it.toByteArray()).joinToString("") { byte ->
            "%02x".format(byte.toInt() and 0xff)
        }
    }
}

internal class AndroidUpdateStatusReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != "${context.packageName}.update.INSTALL_STATUS") return
        val nonce = intent.getStringExtra(EXTRA_NONCE) ?: return
        val sessionId = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1)
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, Int.MIN_VALUE)
        if (sessionId < 0 || status == Int.MIN_VALUE) return
        val userActionIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(Intent.EXTRA_INTENT)
        }
        if (!InstallStatusRegistry.dispatch(nonce, intent.action.orEmpty(), sessionId, status, userActionIntent)) {
            runCatching { context.packageManager.packageInstaller.abandonSession(sessionId) }
        }
    }

    companion object {
        const val EXTRA_NONCE = "io.github.xiangwang2000.dnsshield.update.EXTRA_NONCE"
    }
}

private const val INSTALL_SESSION_TIMEOUT_MILLIS = 15 * 60 * 1000L

private data class InstallStatusEvent(val status: Int, val userActionIntent: Intent?)

private class InstallStatusRoute(
    val nonce: String,
    val action: String,
    val sessionId: Int,
) {
    val events = Channel<InstallStatusEvent>(Channel.UNLIMITED)
}

private object InstallStatusRegistry {
    private val routes = ConcurrentHashMap<String, InstallStatusRoute>()

    fun register(nonce: String, action: String, sessionId: Int): InstallStatusRoute =
        InstallStatusRoute(nonce, action, sessionId).also { routes[nonce] = it }

    fun unregister(route: InstallStatusRoute) {
        routes.remove(route.nonce, route)
        route.events.close()
    }

    fun dispatch(
        nonce: String,
        action: String,
        sessionId: Int,
        status: Int,
        userActionIntent: Intent?,
    ): Boolean {
        val route = routes[nonce] ?: return false
        if (route.action != action || route.sessionId != sessionId) return true
        route.events.trySend(InstallStatusEvent(status, userActionIntent))
        return true
    }
}
