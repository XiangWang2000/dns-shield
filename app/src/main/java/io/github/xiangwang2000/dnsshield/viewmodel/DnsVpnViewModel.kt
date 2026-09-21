package io.github.xiangwang2000.dnsshield.viewmodel

import android.app.Application
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Drawable
import android.util.Log
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.BypassedApp
import io.github.xiangwang2000.dnsshield.data.DnsServer
import io.github.xiangwang2000.dnsshield.service.DnsDiagnosticsSnapshot
import io.github.xiangwang2000.dnsshield.service.DnsVpnService
import io.github.xiangwang2000.dnsshield.service.VpnLifecycleState
import io.github.xiangwang2000.dnsshield.service.VpnToggleAction
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AppInfo(
    val packageName: String,
    val appName: String,
    val isBypassed: Boolean
)

data class DnsShieldUiState(
    val isRunning: Boolean = false,
    val vpnLifecycleState: VpnLifecycleState = VpnLifecycleState.STOPPED,
    val diagnostics: DnsDiagnosticsSnapshot = DnsDiagnosticsSnapshot(),
    val activeDns: String = "None",
    val logs: List<String> = emptyList(),
    val dnsServers: List<DnsServer> = emptyList(),
    val activeDnsServer: DnsServer? = null,
    val appSearchQuery: String = "",
    val filteredApps: List<AppInfo> = emptyList(),
    val isLoadingApps: Boolean = false,
    val vpnSettingsModified: Boolean = false,
    val infoCardVisible: Boolean = true
) {
    val queryCount: Long get() = diagnostics.received
    val blockedAds: Long get() = diagnostics.blocked
    val savedBytes: Long get() = diagnostics.estimatedSavedBytes
}

data class VpnMetricsState(
    val diagnostics: DnsDiagnosticsSnapshot,
    val logs: List<String>
)

data class VpnStatusAndDnsState(
    val lifecycleState: VpnLifecycleState,
    val activeDns: String,
    val dnsServers: List<DnsServer>,
    val activeDnsServer: DnsServer?
) {
    val isRunning: Boolean get() = lifecycleState.isRunning
}

data class AppListState(
    val searchQuery: String,
    val filteredApps: List<AppInfo>,
    val isLoadingApps: Boolean
)

object AppIconCache {
    private val cache = android.util.LruCache<String, Drawable>(128)

    fun get(packageName: String): Drawable? {
        synchronized(this) {
            return cache.get(packageName)
        }
    }

    fun put(packageName: String, drawable: Drawable) {
        synchronized(this) {
            cache.put(packageName, drawable)
        }
    }

    fun clear() {
        synchronized(this) {
            cache.evictAll()
        }
    }
}

class DnsVpnViewModel(application: Application) : AndroidViewModel(application) {

    private val db = AppDatabase.getDatabase(application)
    private val dnsDao = db.dnsDao()
    private val sharedPrefs = application.getSharedPreferences("dns_shield_prefs", Context.MODE_PRIVATE)

    private val _vpnLifecycleState = MutableStateFlow(DnsVpnService.lifecycleStateFlow.value)
    val vpnLifecycleState = _vpnLifecycleState.asStateFlow()

    private val _diagnostics = MutableStateFlow(DnsVpnService.diagnosticsFlow.value)

    private val _activeDns = MutableStateFlow(DnsVpnService.activeDnsFlow.value)
    val activeDns = _activeDns.asStateFlow()

    private val _liveLogs = MutableStateFlow<List<String>>(DnsVpnService.liveLogsFlow.value)
    val liveLogs = _liveLogs.asStateFlow()

    val vpnSettingsModified = MutableStateFlow(false)

    private val _infoCardVisible = MutableStateFlow(sharedPrefs.getBoolean("info_card_visible", true))

    private fun addLog(message: String) {
        DnsVpnService.addLog(message)
    }

    // DNS Servers list
    val dnsServers = dnsDao.getDnsServersFlow().stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptyList()
    )

    // Current active DNS server configuration in DB
    val activeDnsServer = dnsDao.getActiveDnsServerFlow().stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = null
    )

    // Exempt list search queries
    private val _searchQuery = MutableStateFlow("")
    val searchQuery = _searchQuery.asStateFlow()

    private val _isLoadingApps = MutableStateFlow(false)
    val isLoadingApps = _isLoadingApps.asStateFlow()

    // Raw list of installed apps
    private val _installedApps = MutableStateFlow<List<AppInfo>>(emptyList())

    // Combined Flow to provide a filtered, reactive app list
    val filteredApps = combine(_installedApps, _searchQuery) { apps, query ->
        if (query.isBlank()) {
            apps
        } else {
            apps.filter {
                it.appName.contains(query, ignoreCase = true) ||
                        it.packageName.contains(query, ignoreCase = true)
            }
        }
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptyList()
    )

    private val vpnMetricsStateFlow: Flow<VpnMetricsState> = combine(
        _diagnostics,
        _liveLogs
    ) { diagnostics, logs ->
        VpnMetricsState(diagnostics, logs)
    }

    private val vpnStatusAndDnsStateFlow: Flow<VpnStatusAndDnsState> = combine(
        _vpnLifecycleState,
        _activeDns,
        dnsServers,
        activeDnsServer
    ) { lifecycleState, activeDns, servers, activeServer ->
        VpnStatusAndDnsState(lifecycleState, activeDns, servers, activeServer)
    }

    private val appListStateFlow: Flow<AppListState> = combine(
        _searchQuery,
        filteredApps,
        _isLoadingApps
    ) { query, apps, loading ->
        AppListState(query, apps, loading)
    }

    val uiState: StateFlow<DnsShieldUiState> = combine(
        vpnMetricsStateFlow,
        vpnStatusAndDnsStateFlow,
        appListStateFlow,
        vpnSettingsModified,
        _infoCardVisible
    ) { metrics, statusDns, appList, settingsModified, infoVisible ->
        DnsShieldUiState(
            isRunning = statusDns.isRunning,
            vpnLifecycleState = statusDns.lifecycleState,
            diagnostics = metrics.diagnostics,
            activeDns = statusDns.activeDns,
            logs = metrics.logs,
            dnsServers = statusDns.dnsServers,
            activeDnsServer = statusDns.activeDnsServer,
            appSearchQuery = appList.searchQuery,
            filteredApps = appList.filteredApps,
            isLoadingApps = appList.isLoadingApps,
            vpnSettingsModified = settingsModified,
            infoCardVisible = infoVisible
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = DnsShieldUiState(
            isRunning = _vpnLifecycleState.value.isRunning,
            vpnLifecycleState = _vpnLifecycleState.value,
            diagnostics = _diagnostics.value,
            activeDns = _activeDns.value,
            logs = _liveLogs.value,
            dnsServers = emptyList(),
            activeDnsServer = null,
            appSearchQuery = _searchQuery.value,
            filteredApps = emptyList(),
            isLoadingApps = _isLoadingApps.value,
            vpnSettingsModified = vpnSettingsModified.value,
            infoCardVisible = _infoCardVisible.value
        )
    )

    fun setInfoCardVisible(visible: Boolean) {
        _infoCardVisible.value = visible
        viewModelScope.launch(Dispatchers.IO) {
            sharedPrefs.edit().putBoolean("info_card_visible", visible).apply()
        }
    }

    private fun <T> collectServiceFlow(
        source: StateFlow<T>,
        target: MutableStateFlow<T>
    ) {
        viewModelScope.launch {
            source.collect { target.value = it }
        }
    }

    private var hasLoadedApps = false

    init {
        // Direct, high-speed StateFlow collections across the same process using clean helper method
        collectServiceFlow(DnsVpnService.lifecycleStateFlow, _vpnLifecycleState)
        collectServiceFlow(DnsVpnService.diagnosticsFlow, _diagnostics)
        collectServiceFlow(DnsVpnService.activeDnsFlow, _activeDns)
        collectServiceFlow(DnsVpnService.liveLogsFlow, _liveLogs)

        // Observe bypassed apps list database and re-evaluate installed apps isBypassed status
        viewModelScope.launch {
            dnsDao.getBypassedAppsFlow().collect { dbBypassedApps ->
                evaluateAppBypassStatus(dbBypassedApps)
            }
        }
    }

    fun setSearchQuery(query: String) {
        _searchQuery.value = query
    }

    fun refreshInstalledAppsIfNeeded() {
        if (hasLoadedApps) return
        hasLoadedApps = true
        refreshInstalledApps()
    }

    fun refreshInstalledApps() {
        viewModelScope.launch {
            _isLoadingApps.value = true

            val mapped = withContext(Dispatchers.IO) {
                val apps = getInstalledLauncherApps()
                val currentBypassed = dnsDao.getBypassedAppsList()
                val bypassedSet = currentBypassed.map { it.packageName }.toSet()

                apps.map { app ->
                    app.copy(isBypassed = app.packageName in bypassedSet)
                }.sortedBy { it.appName.lowercase() }
            }

            _installedApps.value = mapped
            _isLoadingApps.value = false
        }
    }

    private fun evaluateAppBypassStatus(dbBypassedApps: List<BypassedApp>) {
        val bypassedSet = dbBypassedApps.map { it.packageName }.toSet()
        val mapped = _installedApps.value.map { app ->
            app.copy(isBypassed = app.packageName in bypassedSet)
        }
        _installedApps.value = mapped
    }

    private fun getInstalledLauncherApps(): List<AppInfo> {
        val pm = getApplication<Application>().packageManager
        val mainIntent = Intent(Intent.ACTION_MAIN, null).apply {
            addCategory(Intent.CATEGORY_LAUNCHER)
        }
        val resolveInfos = pm.queryIntentActivities(mainIntent, 0)
        val ownPackageName = getApplication<Application>().packageName

        val list = mutableListOf<AppInfo>()
        val processedPackages = mutableSetOf<String>()

        for (resolveInfo in resolveInfos) {
            val packageName = resolveInfo.activityInfo.packageName
            if (packageName == ownPackageName || processedPackages.contains(packageName)) {
                continue
            }
            processedPackages.add(packageName)

            try {
                val appLabel = resolveInfo.loadLabel(pm).toString()
                list.add(AppInfo(packageName, appLabel, isBypassed = false))
            } catch (e: Exception) {
                // Ignore application loading failure
            }
        }
        return list
    }

    fun toggleAppBypass(packageName: String, appName: String, shouldBypass: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            if (shouldBypass) {
                dnsDao.insertBypassedApp(BypassedApp(packageName, appName, isBypassed = true))
                addLog("新增排除應用: $appName ($packageName)")
            } else {
                dnsDao.deleteBypassedAppByPackage(packageName)
                addLog("將排除名單中移除: $appName")
            }

            // If VPN is running, warn that a restart will capture the new split tunnel
            if (_vpnLifecycleState.value == VpnLifecycleState.RUNNING) {
                vpnSettingsModified.value = true
                addLog("提示：排除規則已更新。請點擊「立即重啟」以套用新設定。")
            }
        }
    }

    fun selectDnsServer(serverId: Int) {
        viewModelScope.launch(Dispatchers.IO) {
            val success = dnsDao.setActiveDnsServer(serverId)
            if (!success) {
                addLog("DNS 切換失敗：找不到指定的 DNS Server id=$serverId")
                return@launch
            }
            val selected = dnsDao.getActiveDnsServer()
            if (selected != null) {
                // Use cross-process UPDATE_DNS intent command
                val intent = Intent(getApplication(), DnsVpnService::class.java).apply {
                    action = DnsVpnService.ACTION_UPDATE_DNS
                    putExtra("primary", selected.primaryIp)
                    putExtra("secondary", selected.secondaryIp)
                    putExtra("dnsName", selected.name)
                }
                getApplication<Application>().startService(intent)
            }
        }
    }

    fun addCustomDnsServer(name: String, primaryIp: String, secondaryIp: String?) {
        viewModelScope.launch(Dispatchers.IO) {
            val trimmedName = name.trim()
            val trimmedPrimary = primaryIp.trim()
            val trimmedSec = secondaryIp?.trim()?.let { if (it.isBlank()) null else it }

            if (trimmedName.isEmpty() || trimmedPrimary.isEmpty()) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(getApplication(), "名稱與主要 IP 不可空白", Toast.LENGTH_SHORT).show()
                }
                return@launch
            }

            val currentServers = dnsServers.value
            if (currentServers.any { it.name.equals(trimmedName, ignoreCase = true) }) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(getApplication(), "DNS 伺服器名稱「$trimmedName」已存在", Toast.LENGTH_SHORT).show()
                }
                return@launch
            }
            if (currentServers.any { it.primaryIp == trimmedPrimary && it.secondaryIp == trimmedSec }) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(getApplication(), "相同的主要與次要 IP 組合已存在於其他伺服器中", Toast.LENGTH_SHORT).show()
                }
                return@launch
            }
            if (currentServers.any { it.primaryIp == trimmedPrimary }) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(getApplication(), "DNS 主要 IP「$trimmedPrimary」已存在", Toast.LENGTH_SHORT).show()
                }
                return@launch
            }

            val newDns = DnsServer(
                name = trimmedName,
                primaryIp = trimmedPrimary,
                secondaryIp = trimmedSec,
                isCustom = true,
                isActive = false
            )
            dnsDao.insertDnsServer(newDns)
            addLog("新增自訂 DNS：${newDns.name} (${newDns.primaryIp})")
            withContext(Dispatchers.Main) {
                Toast.makeText(getApplication(), "已成功新增 DNS：${trimmedName}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun deleteDnsServer(server: DnsServer) {
        viewModelScope.launch(Dispatchers.IO) {
            val success = dnsDao.deleteDnsServerSafely(server.id)
            if (!success) {
                addLog("無法刪除 DNS：至少需要保留一組 DNS Server")
                withContext(Dispatchers.Main) {
                    Toast.makeText(getApplication(), "不可刪除！至少需要保留一組 DNS 伺服器", Toast.LENGTH_SHORT).show()
                }
                return@launch
            }
            addLog("刪除 DNS 設定：${server.name}")
            // If deleted the active one, fallback is handled inside transaction; we notify service here with the new active DNS
            if (server.isActive) {
                val newActive = dnsDao.getActiveDnsServer()
                if (newActive != null) {
                    // Use cross-process UPDATE_DNS intent command
                    val intent = Intent(getApplication(), DnsVpnService::class.java).apply {
                        action = DnsVpnService.ACTION_UPDATE_DNS
                        putExtra("primary", newActive.primaryIp)
                        putExtra("secondary", newActive.secondaryIp)
                        putExtra("dnsName", newActive.name)
                    }
                    getApplication<Application>().startService(intent)
                }
            }
        }
    }

    fun toggleVpn(context: Context) {
        try {
            when (_vpnLifecycleState.value.toggleAction()) {
                VpnToggleAction.NONE -> return
                VpnToggleAction.STOP -> {
                    vpnSettingsModified.value = false
                    addLog("[安全防護] 已送出關閉防護服務的要求…")
                    val intent = Intent(context, DnsVpnService::class.java).apply {
                        action = DnsVpnService.ACTION_STOP
                    }
                    context.startService(intent)
                }
                VpnToggleAction.START -> {
                    vpnSettingsModified.value = false
                    val intent = Intent(context, DnsVpnService::class.java).apply {
                        action = DnsVpnService.ACTION_START
                    }
                    ContextCompat.startForegroundService(context, intent)
                }
            }
        } catch (e: Exception) {
            Log.e("DnsVpnViewModel", "Failed to start/stop VPN service", e)
            addLog("無法啟動/關閉安全偵測服務：${e.localizedMessage}")
        }
    }

    fun restartVpn(context: Context) {
        viewModelScope.launch {
            try {
                // Clear modified layout state
                vpnSettingsModified.value = false

                // Directly send non-destructive RESTART action to the service
                val restartIntent = Intent(context, DnsVpnService::class.java).apply {
                    action = DnsVpnService.ACTION_RESTART
                }
                ContextCompat.startForegroundService(context, restartIntent)
            } catch (e: Exception) {
                Log.e("DnsVpnViewModel", "Failed to restart VPN", e)
                addLog("無法重新啟動防護服務：${e.message}")
            }
        }
    }

    fun clearVpnLogs() {
        val intent = Intent(getApplication(), DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_CLEAR_LOGS
        }
        getApplication<Application>().startService(intent)

        // snappiness backup values
        _liveLogs.value = emptyList()
        _diagnostics.value = DnsDiagnosticsSnapshot()
    }
}
