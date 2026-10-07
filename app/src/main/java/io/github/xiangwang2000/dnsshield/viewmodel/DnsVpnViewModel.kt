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
import io.github.xiangwang2000.dnsshield.blocking.DomainNameNormalizer
import io.github.xiangwang2000.dnsshield.blocking.DomainRuleAction
import io.github.xiangwang2000.dnsshield.blocking.PublicSuffixResolverOwner
import io.github.xiangwang2000.dnsshield.blocking.UserDomainRuleValidation
import io.github.xiangwang2000.dnsshield.blocking.UserDomainRuleValidator
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.BypassedApp
import io.github.xiangwang2000.dnsshield.data.DnsServer
import io.github.xiangwang2000.dnsshield.service.DnsDiagnosticsSnapshot
import io.github.xiangwang2000.dnsshield.blocking.RulePolicyStatus
import io.github.xiangwang2000.dnsshield.data.UserDomainRuleEntity
import io.github.xiangwang2000.dnsshield.service.DnsDecisionEvent
import io.github.xiangwang2000.dnsshield.service.DnsVpnService
import io.github.xiangwang2000.dnsshield.service.DohEndpointConfiguration
import io.github.xiangwang2000.dnsshield.service.ResolverCommandRuntime
import io.github.xiangwang2000.dnsshield.service.VpnLifecycleState
import io.github.xiangwang2000.dnsshield.service.VpnToggleAction
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.util.concurrent.atomic.AtomicBoolean
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
    val dnsTransportStatus: String = "尚無上游查詢",
    val logs: List<String> = emptyList(),
    val userDomainRules: List<UserDomainRuleEntity> = emptyList(),
    val domainRuleSearchQuery: String = "",
    val blockedEvents: List<DnsDecisionEvent> = emptyList(),
    val dnsServers: List<DnsServer> = emptyList(),
    val activeDnsServer: DnsServer? = null,
    val appSearchQuery: String = "",
    val filteredApps: List<AppInfo> = emptyList(),
    val isLoadingApps: Boolean = false,
    val vpnSettingsModified: Boolean = false,
    val infoCardVisible: Boolean = true,
    val rulePolicyStatus: RulePolicyStatus = RulePolicyStatus()
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
    val dnsTransportStatus: String,
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

data class DomainRulesAndEventsState(
    val rules: List<UserDomainRuleEntity>,
    val searchQuery: String,
    val blockedEvents: List<DnsDecisionEvent>,
    val infoCardVisible: Boolean
)

data class DomainRuleUndoToken(
    val domain: String,
    val includeSubdomains: Boolean,
    val expectedRevision: String,
    val previous: UserDomainRuleEntity?
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
    private val resolverCommandCoordinator = ResolverCommandRuntime.coordinator
    internal var resolverCommandOperations = ResolverCommandOperations(
        setActiveDnsServer = dnsDao::setActiveDnsServer,
        getActiveDnsServer = dnsDao::getActiveDnsServer,
        updatePlaintextFallback = dnsDao::updatePlaintextFallback,
        deleteDnsServerSafely = dnsDao::deleteDnsServerSafely,
        dispatch = ::sendResolverUpdate
    )
    internal var resolverCommandWaiterScope: CoroutineScope = viewModelScope
    private val sharedPrefs = application.getSharedPreferences("dns_shield_prefs", Context.MODE_PRIVATE)
    private val publicSuffixResolverOwner by lazy {
        PublicSuffixResolverOwner.fromAssets(application.assets)
    }

    private val _vpnLifecycleState = MutableStateFlow(DnsVpnService.lifecycleStateFlow.value)
    val vpnLifecycleState = _vpnLifecycleState.asStateFlow()

    private val _diagnostics = MutableStateFlow(DnsVpnService.diagnosticsFlow.value)

    private val _activeDns = MutableStateFlow(DnsVpnService.activeDnsFlow.value)
    val activeDns = _activeDns.asStateFlow()

    private val _dnsTransportStatus = MutableStateFlow(DnsVpnService.dnsTransportStatusFlow.value)

    private val _liveLogs = MutableStateFlow<List<String>>(DnsVpnService.liveLogsFlow.value)
    val liveLogs = _liveLogs.asStateFlow()

    private val _blockedEvents = MutableStateFlow(DnsVpnService.liveDecisionEventsFlow.value)
    private val _domainRuleSearchQuery = MutableStateFlow("")

    private val userDomainRules = dnsDao.getUserDomainRulesFlow().stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptyList()
    )
    private val _rulePolicyStatus = MutableStateFlow(DnsVpnService.rulePolicyStatusFlow.value)

    val vpnSettingsModified = MutableStateFlow(false)

    private val _infoCardVisible = MutableStateFlow(sharedPrefs.getBoolean("info_card_visible", true))

    private fun addLog(message: String) {
        DnsVpnService.addLog(message)
    }

    private suspend fun showResolverCommandMessage(message: String, duration: Int = Toast.LENGTH_LONG) {
        addLog(message)
        withContext(Dispatchers.Main) {
            Toast.makeText(getApplication(), message, duration).show()
        }
    }

    private suspend fun reportResolverCommandFailure(
        operation: String,
        exception: Exception,
        message: String
    ) {
        Log.e("DnsVpnViewModel", operation, exception)
        showResolverCommandMessage(message)
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
        _dnsTransportStatus,
        dnsServers,
        activeDnsServer
    ) { lifecycleState, activeDns, transportStatus, servers, activeServer ->
        VpnStatusAndDnsState(lifecycleState, activeDns, transportStatus, servers, activeServer)
    }

    private val appListStateFlow: Flow<AppListState> = combine(
        _searchQuery,
        filteredApps,
        _isLoadingApps
    ) { query, apps, loading ->
        AppListState(query, apps, loading)
    }

    private val domainRulesAndEventsStateFlow: Flow<DomainRulesAndEventsState> = combine(
        userDomainRules,
        _domainRuleSearchQuery,
        _blockedEvents,
        _infoCardVisible
    ) { rules, query, events, infoVisible ->
        DomainRulesAndEventsState(rules, query, events, infoVisible)
    }

    private val baseUiState: Flow<DnsShieldUiState> = combine(
        vpnMetricsStateFlow,
        vpnStatusAndDnsStateFlow,
        appListStateFlow,
        domainRulesAndEventsStateFlow,
        vpnSettingsModified
    ) { metrics, statusDns, appList, ruleState, settingsModified ->
        DnsShieldUiState(
            isRunning = statusDns.isRunning,
            vpnLifecycleState = statusDns.lifecycleState,
            diagnostics = metrics.diagnostics,
            activeDns = statusDns.activeDns,
            dnsTransportStatus = statusDns.dnsTransportStatus,
            logs = metrics.logs,
            userDomainRules = ruleState.rules,
            domainRuleSearchQuery = ruleState.searchQuery,
            blockedEvents = ruleState.blockedEvents,
            dnsServers = statusDns.dnsServers,
            activeDnsServer = statusDns.activeDnsServer,
            appSearchQuery = appList.searchQuery,
            filteredApps = appList.filteredApps,
            isLoadingApps = appList.isLoadingApps,
            vpnSettingsModified = settingsModified,
            infoCardVisible = ruleState.infoCardVisible
        )
    }

    val uiState: StateFlow<DnsShieldUiState> = combine(
        baseUiState,
        _rulePolicyStatus
    ) { state, rulePolicyStatus ->
        state.copy(rulePolicyStatus = rulePolicyStatus)
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = DnsShieldUiState(
            isRunning = _vpnLifecycleState.value.isRunning,
            vpnLifecycleState = _vpnLifecycleState.value,
            diagnostics = _diagnostics.value,
            activeDns = _activeDns.value,
            dnsTransportStatus = _dnsTransportStatus.value,
            logs = _liveLogs.value,
            userDomainRules = userDomainRules.value,
            domainRuleSearchQuery = _domainRuleSearchQuery.value,
            blockedEvents = _blockedEvents.value,
            dnsServers = emptyList(),
            activeDnsServer = null,
            appSearchQuery = _searchQuery.value,
            filteredApps = emptyList(),
            isLoadingApps = _isLoadingApps.value,
            vpnSettingsModified = vpnSettingsModified.value,
            infoCardVisible = _infoCardVisible.value,
            rulePolicyStatus = _rulePolicyStatus.value
        )
    )

    fun setInfoCardVisible(visible: Boolean) {
        _infoCardVisible.value = visible
        viewModelScope.launch(Dispatchers.IO) {
            sharedPrefs.edit().putBoolean("info_card_visible", visible).apply()
        }
    }

    fun setDomainRuleSearchQuery(query: String) {
        _domainRuleSearchQuery.value = query
    }

    suspend fun saveDomainRule(
        input: String,
        action: DomainRuleAction,
        includeSubdomains: Boolean
    ): String? = withContext(Dispatchers.IO) {
        val resolver = if (includeSubdomains) {
            publicSuffixResolverOwner.resolverOrNull()
        } else {
            null
        }
        val rule = when (
            val validation = UserDomainRuleValidator.validate(
                domain = input,
                action = action,
                includeSubdomains = includeSubdomains,
                resolver = resolver
            )
        ) {
            is UserDomainRuleValidation.Valid -> validation.rule
            is UserDomainRuleValidation.Invalid -> return@withContext when (validation.reason) {
                UserDomainRuleValidation.Reason.INVALID_DOMAIN -> "請輸入有效的網域名稱。"
                UserDomainRuleValidation.Reason.PUBLIC_SUFFIX_RESOLVER_UNAVAILABLE ->
                    "目前無法驗證公共後綴，請稍後再試。"
                UserDomainRuleValidation.Reason.PUBLIC_SUFFIX_DOMAIN ->
                    "公共後綴不能套用到所有子網域。"
            }
        }

        try {
            dnsDao.insertUserDomainRule(
                UserDomainRuleEntity(
                    domain = rule.domain,
                    action = rule.action.name,
                    includeSubdomains = rule.includeSubdomains
                )
            )
            addLog("[網域規則] 已儲存 ${rule.domain}（${rule.action.name}）。")
            requestDomainPolicyReloadIfRunning()
            null
        } catch (exception: Exception) {
            Log.e("DnsVpnViewModel", "Failed to save user domain rule", exception)
            "儲存規則失敗：${exception.localizedMessage ?: "資料庫錯誤"}"
        }
    }

    suspend fun deleteDomainRule(rule: UserDomainRuleEntity) = withContext(Dispatchers.IO) {
        try {
            dnsDao.deleteUserDomainRule(rule.domain, rule.includeSubdomains)
            addLog("[網域規則] 已刪除 ${rule.domain}。")
            requestDomainPolicyReloadIfRunning()
        } catch (exception: Exception) {
            Log.e("DnsVpnViewModel", "Failed to delete user domain rule", exception)
            addLog("[網域規則] 刪除 ${rule.domain} 失敗：${exception.localizedMessage ?: "資料庫錯誤"}")
        }
    }

    suspend fun allowBlockedDomain(domain: String): DomainRuleUndoToken = withContext(Dispatchers.IO) {
        val validated = UserDomainRuleValidator.validate(
            domain = domain,
            action = DomainRuleAction.ALLOW,
            includeSubdomains = false
        ) as? UserDomainRuleValidation.Valid
            ?: throw IllegalArgumentException("攔截事件中的網域格式無效")
        val rule = UserDomainRuleEntity(
            domain = validated.rule.domain,
            action = DomainRuleAction.ALLOW.name,
            includeSubdomains = false
        )
        val previous = dnsDao.replaceUserDomainRule(rule)
        addLog("[網域規則] 已為 ${rule.domain} 新增精確允許規則。")
        requestDomainPolicyReloadIfRunning()
        DomainRuleUndoToken(
            domain = rule.domain,
            includeSubdomains = false,
            expectedRevision = rule.revision,
            previous = previous
        )
    }

    suspend fun undoDomainRule(token: DomainRuleUndoToken): Boolean = withContext(Dispatchers.IO) {
        val restored = dnsDao.restoreUserDomainRule(
            domain = token.domain,
            includeSubdomains = token.includeSubdomains,
            expectedRevision = token.expectedRevision,
            previous = token.previous
        )
        if (restored) {
            addLog("[網域規則] 已復原 ${token.domain} 的規則變更。")
            requestDomainPolicyReloadIfRunning()
        }
        restored
    }

    private fun requestDomainPolicyReloadIfRunning() {
        if (DnsVpnService.lifecycleStateFlow.value != VpnLifecycleState.RUNNING) return
        val intent = Intent(getApplication(), DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_RELOAD_DOMAIN_POLICY
        }
        try {
            getApplication<Application>().startService(intent)
        } catch (exception: Exception) {
            Log.e("DnsVpnViewModel", "Failed to request active domain policy reload", exception)
            addLog("[網域規則] 新設定已儲存，VPN 規則同步失敗；請重新啟動防護服務。")
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
        collectServiceFlow(DnsVpnService.dnsTransportStatusFlow, _dnsTransportStatus)
        collectServiceFlow(DnsVpnService.liveLogsFlow, _liveLogs)
        collectServiceFlow(DnsVpnService.liveDecisionEventsFlow, _blockedEvents)
        collectServiceFlow(DnsVpnService.rulePolicyStatusFlow, _rulePolicyStatus)

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
        val persisted = AtomicBoolean(false)
        val operations = resolverCommandOperations
        val submission = resolverCommandCoordinator.submit { revision ->
            if (!operations.setActiveDnsServer(serverId)) {
                ResolverCommandApplyStatus.NOT_SAVED
            } else {
                persisted.set(true)
                val activeServer = operations.getActiveDnsServer()
                if (resolverCommandCoordinator.dispatchIfCurrent(revision, activeServer, operations.dispatch)) {
                    ResolverCommandApplyStatus.APPLIED
                } else {
                    ResolverCommandApplyStatus.SAVED_UNSYNCED
                }
            }
        }
        resolverCommandWaiterScope.launch(Dispatchers.IO) {
            when (val result = awaitResolverCommandResult(submission.result, persisted)) {
                is ResolverCommandResult.Completed -> {
                    when (result.value) {
                        ResolverCommandApplyStatus.NOT_SAVED ->
                            showResolverCommandMessage("找不到這組 DNS，請重新選擇。")
                        ResolverCommandApplyStatus.SAVED_UNSYNCED ->
                            addLog(ResolverCommandFailureMessages.SELECT_SAVED_UNSYNCED)
                        ResolverCommandApplyStatus.APPLIED -> Unit
                    }
                }
                is ResolverCommandResult.Failed -> {
                    reportResolverCommandFailure(
                        "DNS selection command failed",
                        result.cause,
                        if (result.persisted) {
                            ResolverCommandFailureMessages.SELECT_SAVED_UNSYNCED
                        } else {
                            ResolverCommandFailureMessages.SELECT_NOT_SAVED
                        }
                    )
                }
            }
        }
    }
    private fun sendResolverUpdate(server: DnsServer, revision: Long) {
        val intent = Intent(getApplication(), DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_UPDATE_DNS
            putExtra("resolverId", server.id)
            putExtra(DnsVpnService.EXTRA_RESOLVER_COMMAND_REVISION, revision)
        }
        getApplication<Application>().startService(intent)
    }

    fun setPlaintextFallback(server: DnsServer, allow: Boolean) {
        if (!allow && !DohEndpointConfiguration.hasUsableEncryptedEndpoint(server)) {
            val message = DohEndpointConfiguration.STRICT_MODE_REQUIRES_ENDPOINT_ERROR
            addLog("無法啟用僅加密模式：$message")
            Toast.makeText(getApplication(), message, Toast.LENGTH_LONG).show()
            return
        }

        val persisted = AtomicBoolean(false)
        val operations = resolverCommandOperations
        val submission = resolverCommandCoordinator.submitFallbackPolicy(
            server.id,
            onSubmitted = {
                if (!allow) DnsVpnService.requestPlaintextFallbackAllowed(server.id, false)
            }
        ) { revision, applyRuntimeFence ->
            persistFallbackPolicy(
                allow = allow,
                applyRuntimePolicy = { allowed ->
                    applyRuntimeFence {
                        DnsVpnService.requestPlaintextFallbackAllowed(server.id, allowed)
                        DnsVpnService.setPlaintextFallbackAllowed(server.id, allowed)
                    }
                },
                onPersisted = { persisted.set(true) },
                persist = { operations.updatePlaintextFallback(server.id, allow) > 0 },
                dispatch = {
                    val activeServer = operations.getActiveDnsServer()
                    resolverCommandCoordinator.dispatchIfCurrent(revision, activeServer, operations.dispatch)
                }
            )
        }
        resolverCommandWaiterScope.launch(Dispatchers.IO) {
            when (val result = awaitResolverCommandResult(submission.result, persisted)) {
                is ResolverCommandResult.Completed -> {
                    when (result.value) {
                        ResolverCommandApplyStatus.APPLIED ->
                            addLog(
                                if (allow) "DNS 傳輸政策已設為加密優先，可在 DoH 失敗時降級 UDP/53"
                                else "DNS 傳輸政策已設為僅加密；DoH 無法使用時將回覆 SERVFAIL"
                            )
                        ResolverCommandApplyStatus.NOT_SAVED ->
                            showResolverCommandMessage(
                                if (allow) ResolverCommandFailureMessages.FALLBACK_ALLOW_NOT_SAVED
                                else ResolverCommandFailureMessages.FALLBACK_STRICT_NOT_SAVED
                            )
                        ResolverCommandApplyStatus.SAVED_UNSYNCED ->
                            addLog(ResolverCommandFailureMessages.FALLBACK_SAVED_UNSYNCED)
                    }
                }
                is ResolverCommandResult.Failed -> {
                    reportResolverCommandFailure(
                        "DNS fallback policy command failed",
                        result.cause,
                        if (result.persisted) {
                            if (allow) ResolverCommandFailureMessages.FALLBACK_ALLOW_SAVED_UNSYNCED
                            else ResolverCommandFailureMessages.FALLBACK_STRICT_SAVED_UNSYNCED
                        } else {
                            if (allow) ResolverCommandFailureMessages.FALLBACK_ALLOW_NOT_SAVED
                            else ResolverCommandFailureMessages.FALLBACK_STRICT_NOT_SAVED
                        }
                    )
                }
            }
        }
    }
    fun addCustomDnsServer(
        name: String,
        primaryIp: String,
        secondaryIp: String?,
        allowPlaintextFallback: Boolean = true,
        primaryDohUrl: String? = null,
        primaryDohBootstrapIps: String? = null,
        secondaryDohUrl: String? = null,
        secondaryDohBootstrapIps: String? = null
    ) {
        viewModelScope.launch(Dispatchers.IO) {
            val trimmedName = name.trim()
            val trimmedPrimary = primaryIp.trim()
            val trimmedSec = secondaryIp?.trim()?.let { if (it.isBlank()) null else it }
            val trimmedPrimaryDohUrl = primaryDohUrl?.trim()?.takeIf(String::isNotEmpty)
            val trimmedPrimaryBootstrap = primaryDohBootstrapIps?.trim().orEmpty()
            val trimmedSecondaryDohUrl = secondaryDohUrl?.trim()?.takeIf(String::isNotEmpty)
            val trimmedSecondaryBootstrap = secondaryDohBootstrapIps?.trim().orEmpty()

            if (trimmedName.isEmpty() || trimmedPrimary.isEmpty()) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(getApplication(), "名稱與主要 IP 不可空白", Toast.LENGTH_SHORT).show()
                }
                return@launch
            }

            val dohError = sequenceOf(
                DohEndpointConfiguration.validationError(
                    trimmedPrimaryDohUrl.orEmpty(),
                    trimmedPrimaryBootstrap,
                    strict = !allowPlaintextFallback
                ),
                DohEndpointConfiguration.validationError(
                    trimmedSecondaryDohUrl.orEmpty(),
                    trimmedSecondaryBootstrap,
                    strict = !allowPlaintextFallback
                )
            ).filterNotNull().firstOrNull()
            if (dohError != null) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(getApplication(), dohError, Toast.LENGTH_LONG).show()
                }
                return@launch
            }
            if (!allowPlaintextFallback && !DohEndpointConfiguration.hasUsableEncryptedEndpoint(
                    trimmedPrimary,
                    trimmedSec,
                    trimmedPrimaryDohUrl,
                    trimmedPrimaryBootstrap,
                    trimmedSecondaryDohUrl,
                    trimmedSecondaryBootstrap
                )
            ) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        getApplication(),
                        DohEndpointConfiguration.STRICT_MODE_REQUIRES_ENDPOINT_ERROR,
                        Toast.LENGTH_LONG
                    ).show()
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
                isActive = false,
                allowPlaintextFallback = allowPlaintextFallback,
                primaryDohUrl = trimmedPrimaryDohUrl,
                primaryDohBootstrapIps = DohEndpointConfiguration
                    .parseBootstrapIpv4Addresses(trimmedPrimaryBootstrap)
                    ?.takeIf { it.isNotEmpty() }
                    ?.joinToString(","),
                secondaryDohUrl = trimmedSecondaryDohUrl,
                secondaryDohBootstrapIps = DohEndpointConfiguration
                    .parseBootstrapIpv4Addresses(trimmedSecondaryBootstrap)
                    ?.takeIf { it.isNotEmpty() }
                    ?.joinToString(",")
            )
            dnsDao.insertDnsServer(newDns)
            addLog("新增自訂 DNS：${newDns.name} (${newDns.primaryIp})")
            withContext(Dispatchers.Main) {
                Toast.makeText(getApplication(), "已成功新增 DNS：${trimmedName}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    fun deleteDnsServer(server: DnsServer) {
        val persisted = AtomicBoolean(false)
        val operations = resolverCommandOperations
        val submission = resolverCommandCoordinator.submit { revision ->
            if (!operations.deleteDnsServerSafely(server.id)) {
                ResolverCommandApplyStatus.NOT_SAVED
            } else {
                persisted.set(true)
                val activeServer = operations.getActiveDnsServer()
                if (resolverCommandCoordinator.dispatchIfCurrent(revision, activeServer, operations.dispatch)) {
                    ResolverCommandApplyStatus.APPLIED
                } else {
                    ResolverCommandApplyStatus.SAVED_UNSYNCED
                }
            }
        }
        resolverCommandWaiterScope.launch(Dispatchers.IO) {
            when (val result = awaitResolverCommandResult(submission.result, persisted)) {
                is ResolverCommandResult.Completed -> {
                    when (result.value) {
                        ResolverCommandApplyStatus.NOT_SAVED -> {
                            addLog("無法刪除 DNS：至少需要保留一組 DNS Server")
                            withContext(Dispatchers.Main) {
                                Toast.makeText(getApplication(), "不可刪除！至少需要保留一組 DNS 伺服器", Toast.LENGTH_SHORT).show()
                            }
                        }
                        ResolverCommandApplyStatus.SAVED_UNSYNCED ->
                            addLog(ResolverCommandFailureMessages.DELETE_SAVED_UNSYNCED)
                        ResolverCommandApplyStatus.APPLIED ->
                            addLog("刪除 DNS 設定：" + server.name)
                    }
                }
                is ResolverCommandResult.Failed -> {
                    reportResolverCommandFailure(
                        "DNS deletion command failed",
                        result.cause,
                        if (result.persisted) {
                            ResolverCommandFailureMessages.DELETE_SAVED_UNSYNCED
                        } else {
                            ResolverCommandFailureMessages.DELETE_NOT_SAVED
                        }
                    )
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
        _blockedEvents.value = emptyList()
    }
}
