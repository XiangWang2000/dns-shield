package io.github.xiangwang2000.dnsshield.ui

import android.content.ActivityNotFoundException
import android.text.format.Formatter
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.update.AppUpdateViewModel
import io.github.xiangwang2000.dnsshield.update.UpdatePhase
import kotlinx.coroutines.flow.filterNotNull

@Composable
internal fun AppUpdateAction(model: AppUpdateViewModel = viewModel()) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val state by model.state.collectAsStateWithLifecycle()
    var showDialog by rememberSaveable { mutableStateOf(false) }

    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        model.onInstallPermissionResult()
    }
    LaunchedEffect(lifecycle, context, model) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            model.onForeground()
            model.confirmation.filterNotNull().collect {
                val intent = model.takeInstallConfirmation() ?: return@collect
                try {
                    context.startActivity(intent)
                } catch (_: ActivityNotFoundException) {
                    model.onInstallConfirmationLaunchFailed()
                } catch (_: SecurityException) {
                    model.onInstallConfirmationLaunchFailed()
                }
            }
        }
    }

    IconButton(onClick = { showDialog = true }, modifier = Modifier.testTag("app_update_open")) {
        val updateAvailable = state.phase == UpdatePhase.Available
        BadgedBox(badge = { if (updateAvailable) Badge() }) {
            Icon(
                Icons.Default.SystemUpdate,
                contentDescription = if (updateAvailable) "App 更新，有新版可下載" else "App 更新"
            )
        }
    }

    if (!showDialog) return
    val phase = state.phase
    val downloading = phase == UpdatePhase.Downloading
    AlertDialog(
        modifier = Modifier.semantics { testTagsAsResourceId = true }.testTag("app_update_dialog"),
        onDismissRequest = { if (!downloading) showDialog = false },
        properties = DialogProperties(dismissOnBackPress = !downloading, dismissOnClickOutside = !downloading),
        title = { Text("App 更新") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text("目前版本 v" + BuildConfig.VERSION_NAME, style = MaterialTheme.typography.bodyMedium)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .toggleable(value = state.autoCheck, role = Role.Switch, onValueChange = model::setAutoCheck)
                        .testTag("app_update_auto_check"),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("自動檢查更新", style = MaterialTheme.typography.bodyMedium)
                        Text(
                            "開啟 App 時，每天最多檢查一次。",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    Switch(checked = state.autoCheck, onCheckedChange = null)
                }
                state.available?.let { update ->
                    val size = Formatter.formatShortFileSize(context, update.sizeBytes)
                    Text("新版 v" + update.versionName + " · " + size, style = MaterialTheme.typography.bodyMedium)
                }
                val status = when (phase) {
                    UpdatePhase.Checking -> "正在檢查更新…"
                    UpdatePhase.InstallPermission -> "請在 Android 設定允許 DNS Shield 安裝應用程式。"
                    UpdatePhase.Downloading -> "正在下載並核對更新檔…"
                    UpdatePhase.Installing -> "請在 Android 的安裝畫面確認更新。"
                    else -> state.message
                }
                if (phase == UpdatePhase.Checking || downloading || phase == UpdatePhase.Installing) {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                }
                status?.let {
                    Text(
                        it,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag("app_update_status"),
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                if (phase == UpdatePhase.Available && state.message != null) {
                    TextButton(onClick = model::checkForUpdate, modifier = Modifier.testTag("app_update_check")) {
                        Text("重新檢查")
                    }
                }
            }
        },
        confirmButton = {
            when (phase) {
                UpdatePhase.Idle -> TextButton(onClick = model::checkForUpdate, modifier = Modifier.testTag("app_update_check")) {
                    Text("檢查更新")
                }
                UpdatePhase.Available -> TextButton(
                    onClick = {
                        val permission = model.requestInstall()
                        if (permission != null) {
                            try {
                                permissionLauncher.launch(permission)
                            } catch (_: ActivityNotFoundException) {
                                model.onInstallPermissionLaunchFailed()
                            } catch (_: SecurityException) {
                                model.onInstallPermissionLaunchFailed()
                            }
                        }
                    },
                    modifier = Modifier.testTag("app_update_install")
                ) {
                    Text("下載並安裝")
                }
                UpdatePhase.Downloading -> TextButton(onClick = model::cancelDownload) { Text("取消下載") }
                else -> Unit
            }
        },
        dismissButton = {
            if (!downloading) TextButton(onClick = { showDialog = false }) { Text("關閉") }
        }
    )
}
