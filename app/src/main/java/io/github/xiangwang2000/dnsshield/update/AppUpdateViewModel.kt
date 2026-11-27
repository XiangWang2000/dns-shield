package io.github.xiangwang2000.dnsshield.update

import android.app.Application
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.edit
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.xiangwang2000.dnsshield.BuildConfig
import java.io.File
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.getAndUpdate
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal enum class UpdatePhase {
    Idle, Checking, Available, InstallPermission, Downloading, Installing
}

internal data class AppUpdateUiState(
    val autoCheck: Boolean,
    val phase: UpdatePhase = UpdatePhase.Idle,
    val available: AppUpdate? = null,
    val message: String? = null
)

internal class AppUpdateViewModel(
    application: Application,
    providedReleases: GitHubAppUpdates?
) : AndroidViewModel(application) {
    constructor(application: Application) : this(application, null)

    private val releases by lazy { providedReleases ?: GitHubAppUpdates() }
    private val installer = AndroidUpdateInstaller(application)
    private val downloadDirectory = File(application.cacheDir, "app-updates")
    private val prefs = application.getSharedPreferences("app_updates", Context.MODE_PRIVATE)
    private val _state = MutableStateFlow(
        AppUpdateUiState(
            autoCheck = prefs.getBoolean(AUTO_CHECK, false),
            message = if (prefs.getInt(INSTALL_STARTED_FROM_VERSION_CODE, -1) == BuildConfig.VERSION_CODE) {
                "上次安裝更新已中斷，請重新檢查更新。"
            } else {
                null
            }
        )
    )
    val state = _state.asStateFlow()

    private val _confirmation = MutableStateFlow<Intent?>(null)
    val confirmation = _confirmation.asStateFlow()

    private var operation: Job? = null
    private val operationRunning: Boolean get() = operation?.isCompleted == false

    fun onForeground() {
        if (!_state.value.autoCheck) return
        val now = System.currentTimeMillis()
        val previous = prefs.getLong(LAST_CHECK, 0L)
        if (now - previous !in 0L until CHECK_INTERVAL_MS) checkForUpdate()
    }

    fun setAutoCheck(enabled: Boolean) {
        prefs.edit { putBoolean(AUTO_CHECK, enabled) }
        _state.update { it.copy(autoCheck = enabled) }
        if (enabled) onForeground()
    }

    fun checkForUpdate() {
        if (operationRunning || _state.value.phase == UpdatePhase.InstallPermission) return
        prefs.edit {
            putLong(LAST_CHECK, System.currentTimeMillis())
            remove(INSTALL_STARTED_FROM_VERSION_CODE)
        }
        _state.update { it.copy(phase = UpdatePhase.Checking, available = null, message = null) }
        operation = viewModelScope.launch {
            try {
                val update = releases.check(BuildConfig.VERSION_NAME)
                if (update != null) {
                    showAvailable(update)
                } else {
                    _state.update { it.copy(phase = UpdatePhase.Idle, message = "目前沒有可用的更新。") }
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                Log.w(TAG, "Update check failed: " + error.javaClass.simpleName)
                _state.update { it.copy(phase = UpdatePhase.Idle, message = "無法檢查更新，請確認網路連線後再試。") }
            }
        }
    }

    fun requestInstall(): Intent? {
        val current = _state.value
        val update = current.available ?: return null
        if (operationRunning || current.phase != UpdatePhase.Available) return null
        if (!installer.canInstall()) {
            _state.update { it.copy(phase = UpdatePhase.InstallPermission, message = null) }
            return installer.permissionIntent()
        }
        downloadAndInstall(update)
        return null
    }

    fun onInstallPermissionResult() {
        val current = _state.value
        val update = current.available ?: return
        if (current.phase != UpdatePhase.InstallPermission) return
        if (installer.canInstall()) {
            downloadAndInstall(update)
        } else {
            showAvailable(update, "請允許 DNS Shield 安裝應用程式，再試一次。")
        }
    }

    fun onInstallPermissionLaunchFailed() {
        _state.value.available?.let { showAvailable(it, "無法開啟 Android 的安裝來源設定。") }
    }

    fun takeInstallConfirmation(): Intent? = _confirmation.getAndUpdate { null }

    fun onInstallConfirmationLaunchFailed() {
        _state.value.available?.let { showAvailable(it, "無法開啟 Android 安裝畫面，請再試一次。") }
        operation?.cancel()
    }

    fun cancelDownload() {
        if (_state.value.phase == UpdatePhase.Downloading) operation?.cancel()
    }

    private fun downloadAndInstall(update: AppUpdate) {
        _state.update { it.copy(phase = UpdatePhase.Downloading, message = null) }
        operation = viewModelScope.launch {
            var downloaded: File? = null
            try {
                val apk = releases.download(update, downloadDirectory)
                downloaded = apk
                _state.update { it.copy(phase = UpdatePhase.Installing) }
                withContext(Dispatchers.IO) {
                    // The install can replace this process before it receives the result.
                    prefs.edit(commit = true) {
                        putInt(INSTALL_STARTED_FROM_VERSION_CODE, BuildConfig.VERSION_CODE)
                    }
                }
                when (installer.install(apk, update.versionName) { _confirmation.value = it }) {
                    InstallOutcome.Installed -> _state.update {
                        it.copy(phase = UpdatePhase.Idle, available = null, message = "更新已安裝。")
                    }
                    InstallOutcome.Cancelled -> showAvailable(update, "已取消安裝，可再次下載並安裝。")
                    InstallOutcome.Failed -> showAvailable(update, "Android 無法安裝這個更新，請稍後再試。")
                }
            } catch (error: CancellationException) {
                if (_state.value.phase == UpdatePhase.Downloading) showAvailable(update, "已取消下載。")
                throw error
            } catch (error: Exception) {
                Log.w(TAG, "Update failed: " + error.javaClass.simpleName)
                val message = if (_state.value.phase == UpdatePhase.Downloading) {
                    "無法下載或核對更新檔，請確認網路連線後再試。"
                } else {
                    "無法驗證或安裝更新，請重新檢查新版。"
                }
                showAvailable(update, message)
            } finally {
                _confirmation.value = null
                downloaded?.let { apk ->
                    withContext(NonCancellable + Dispatchers.IO) {
                        prefs.edit(commit = true) { remove(INSTALL_STARTED_FROM_VERSION_CODE) }
                        apk.delete()
                    }
                }
            }
        }
    }

    private fun showAvailable(update: AppUpdate, message: String? = null) {
        _state.update { it.copy(phase = UpdatePhase.Available, available = update, message = message) }
    }

    private companion object {
        const val TAG = "AppUpdate"
        const val AUTO_CHECK = "auto_check"
        const val LAST_CHECK = "last_check"
        const val INSTALL_STARTED_FROM_VERSION_CODE = "install_started_from_version_code"
        const val CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000L
    }
}
