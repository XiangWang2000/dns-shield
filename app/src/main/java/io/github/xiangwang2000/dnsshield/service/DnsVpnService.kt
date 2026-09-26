package io.github.xiangwang2000.dnsshield.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import io.github.xiangwang2000.dnsshield.MainActivity
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyAssembly
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyCacheKey
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyDiagnostics
import io.github.xiangwang2000.dnsshield.blocking.DomainNameNormalizer
import io.github.xiangwang2000.dnsshield.blocking.DomainRuleAction
import io.github.xiangwang2000.dnsshield.blocking.ProductionBlocklistAssetLoader
import io.github.xiangwang2000.dnsshield.blocking.PublicSuffixResolverOwner
import io.github.xiangwang2000.dnsshield.blocking.PublicSuffixResolverStatus
import io.github.xiangwang2000.dnsshield.blocking.ReloadableDomainPolicy
import io.github.xiangwang2000.dnsshield.blocking.RuntimeDomainPolicy
import io.github.xiangwang2000.dnsshield.blocking.RuleBlocklistSource
import io.github.xiangwang2000.dnsshield.blocking.RulePolicyStatus
import io.github.xiangwang2000.dnsshield.blocking.UserDomainRuleValidation
import io.github.xiangwang2000.dnsshield.blocking.UserDomainRuleValidator
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import kotlin.coroutines.resume
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import android.util.LruCache
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ConnectionPool
import okhttp3.Dispatcher

class DnsVpnService : VpnService() {

    companion object {
        const val TAG = "DnsVpnService"
        const val ACTION_START = "io.github.xiangwang2000.dnsshield.service.START"
        const val ACTION_STOP = "io.github.xiangwang2000.dnsshield.service.STOP"
        const val ACTION_RESTART = "io.github.xiangwang2000.dnsshield.service.RESTART"
        const val ACTION_UPDATE_DNS = "io.github.xiangwang2000.dnsshield.service.UPDATE_DNS"
        const val ACTION_CLEAR_LOGS = "io.github.xiangwang2000.dnsshield.service.CLEAR_LOGS"
        const val ACTION_RELOAD_DOMAIN_POLICY = "io.github.xiangwang2000.dnsshield.service.RELOAD_DOMAIN_POLICY"
        private const val CHANNEL_ID = "dns_vpn_channel"
        private const val NOTIFICATION_ID = 5543
        private const val MAX_CONCURRENT_DNS_QUERIES = 24
        private const val MAX_LOG_LINES = 100
        private const val FOREGROUND_LOG_FLUSH_MS = 300L
        private const val FOREGROUND_STATS_FLUSH_MS = 500L
        private const val MEMORY_TRIM_CLEAR_CACHE_LEVEL = 60
        private const val UDP_RESPONSE_BUFFER_SIZE = 4096

        const val VPN_IP = "10.0.0.2"
        const val DUMMY_DNS_IP = "10.0.0.1"

        // Static status flows for real-time UI tracking
        val isRunningFlow = MutableStateFlow(false)
        val queryCountFlow = MutableStateFlow(0)
        val blockedAdsFlow = MutableStateFlow(0)
        val savedBytesFlow = MutableStateFlow(0L)
        val activeDnsFlow = MutableStateFlow("None")
        val liveLogsFlow = MutableStateFlow<List<String>>(emptyList())
        val liveDecisionEventsFlow = MutableStateFlow<List<DnsDecisionEvent>>(emptyList())
        val rulePolicyStatusFlow = MutableStateFlow(RulePolicyStatus.NotLoaded)

        // Atomic counters for perfectly thread-safe, concurrent statistics updates
        val queryCounter = AtomicInteger(0)
        val blockedAdsCounter = AtomicInteger(0)
        val savedBytesCounter = java.util.concurrent.atomic.AtomicLong(0L)

        private val flowFlushScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        private val flushLock = Any()
        private val logsDirty = AtomicBoolean(false)
        private val statsDirty = AtomicBoolean(false)
        @Volatile private var isUiForeground = false
        @Volatile private var logFlushJob: Job? = null
        @Volatile private var statsFlushJob: Job? = null

        // In-memory DNS cache with hash-cached query keys and parsed response TTLs.
        // The query payload is owned by the request coroutine and must not be mutated after use here.
        internal class DnsQueryKey(
            bytes: ByteArray,
            private val resolverGeneration: Int,
            private val policyAssembly: DomainPolicyAssembly
        ) {
            private val bytes = bytes
            private val cachedHashCode = calculateHashCode()
            internal val byteCount: Int
                get() = bytes.size

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is DnsQueryKey) return false
                if (resolverGeneration != other.resolverGeneration) return false
                if (policyAssembly !== other.policyAssembly) return false
                if (bytes.size != other.bytes.size) return false
                for (i in 2 until bytes.size) {
                    if (bytes[i] != other.bytes[i]) return false
                }
                return true
            }

            override fun hashCode(): Int = cachedHashCode

            private fun calculateHashCode(): Int {
                var result = 31 * resolverGeneration + System.identityHashCode(policyAssembly)
                for (i in 2 until bytes.size) {
                    result = 31 * result + bytes[i]
                }
                return result
            }

            fun copyForStorage() = DnsQueryKey(
                bytes = bytes.copyOf(),
                resolverGeneration = resolverGeneration,
                policyAssembly = policyAssembly
            )
        }

        private val dnsCache = LruCache<DnsQueryKey, DnsResponseCacheEntry>(500)
        private val blockDecisionCache = LruCache<DomainPolicyCacheKey, Boolean>(1024)
        private val domainPolicy = ReloadableDomainPolicy()

        // Thread-safe singleton lock for OkHttpClient
        @Volatile private var okHttpClientInstance: OkHttpClient? = null

        fun getOkHttpClient(): OkHttpClient {
            return okHttpClientInstance ?: synchronized(this) {
                okHttpClientInstance ?: OkHttpClient.Builder()
                    .dns(DohBootstrapDns)
                    .dispatcher(
                        Dispatcher().apply {
                            maxRequestsPerHost = MAX_CONCURRENT_DNS_QUERIES
                        }
                    )
                    .connectTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
                    .readTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
                    .writeTimeout(3, java.util.concurrent.TimeUnit.SECONDS)
                    .connectionPool(ConnectionPool(5, 5, java.util.concurrent.TimeUnit.MINUTES))
                    .build().also { okHttpClientInstance = it }
            }
        }

        fun getDoHUrl(ip: String): String? {
            return when (ip) {
                "8.8.8.8", "8.8.4.4" -> "https://dns.google/dns-query"
                "1.1.1.1", "1.0.0.1" -> "https://cloudflare-dns.com/dns-query"
                "94.140.14.14", "94.140.15.15" -> "https://dns.adguard-dns.com/dns-query"
                "9.9.9.9", "149.112.112.112" -> "https://dns.quad9.net/dns-query"
                else -> null
            }
        }

        private fun putCache(key: DnsQueryKey, responseData: ByteArray, query: ParsedDnsQuery) {
            if (key.byteCount < 2) return
            val record = DnsResponseCacheEntry.create(responseData, query) { SystemClock.elapsedRealtime() } ?: return
            synchronized(dnsCache) {
                dnsCache.put(key.copyForStorage(), record)
            }
        }

        private fun getCache(key: DnsQueryKey): ByteArray? {
            if (key.byteCount < 2) return null
            synchronized(dnsCache) {
                val record = dnsCache.get(key) ?: return null
                val response = record.responseAtCurrentTime()
                if (response != null) return response
                dnsCache.remove(key)
            }
            return null
        }

        fun copyResponseWithTxId(responseData: ByteArray, dnsPayload: ByteArray): ByteArray {
            val response = responseData.clone()
            if (response.size >= 2 && dnsPayload.size >= 2) {
                response[0] = dnsPayload[0]
                response[1] = dnsPayload[1]
            }
            return response
        }

        fun clearMemoryCache() {
            synchronized(dnsCache) { dnsCache.evictAll() }
            blockDecisionCache.evictAll()
            addLog("🧹 [記憶體釋放] 已清空 DNS LruCache 解析快取")
        }

        private val logList = mutableListOf<String>()
        private val decisionEvents = mutableListOf<DnsDecisionEvent>()
        private val decisionEventId = AtomicInteger(0)

        fun setUiForeground(isForeground: Boolean) {
            synchronized(flushLock) {
                isUiForeground = isForeground
                logFlushJob?.cancel()
                logFlushJob = null
                statsFlushJob?.cancel()
                statsFlushJob = null
            }
            if (isForeground) {
                logsDirty.set(false)
                statsDirty.set(false)
                flushLogsNow()
                flushStatsNow()
            }
        }

        fun addLog(message: String) {
            addLogInternal(message, writeDebugLog = true)
        }

        private inline fun addDnsQueryLog(important: Boolean = false, message: () -> String) {
            if (!important && !isUiForeground) {
                return
            }
            addLogInternal(message(), writeDebugLog = important || isUiForeground)
        }

        private fun addLogInternal(message: String, writeDebugLog: Boolean) {
            val timestamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
            val formattedMessage = "[$timestamp] $message"
            if (writeDebugLog) {
                Log.d(TAG, formattedMessage)
            }
            synchronized(logList) {
                logList.add(0, formattedMessage) // Add to top (newest first)
                if (logList.size > MAX_LOG_LINES) {
                    logList.removeAt(logList.size - 1)
                }
            }
            scheduleLogFlush()
        }

        private fun logDnsTransportFailure(message: String, error: Throwable? = null) {
            if (!isUiForeground) return
            if (error == null) {
                Log.e(TAG, message)
            } else {
                Log.e(TAG, message, error)
            }
        }

        fun clearLogs() {
            synchronized(logList) {
                logList.clear()
                if (isUiForeground) {
                    liveLogsFlow.value = emptyList()
                }
            }
            synchronized(decisionEvents) {
                decisionEvents.clear()
                liveDecisionEventsFlow.value = emptyList()
            }
            queryCounter.set(0)
            blockedAdsCounter.set(0)
            savedBytesCounter.set(0L)
            if (isUiForeground) {
                flushStatsNow()
            }
        }

        fun recordResolvedQuery() {
            queryCounter.incrementAndGet()
            scheduleStatsFlush()
        }

        fun recordBlockedQuery(savedInBytes: Long) {
            blockedAdsCounter.incrementAndGet()
            savedBytesCounter.addAndGet(savedInBytes)
            queryCounter.incrementAndGet()
            scheduleStatsFlush()
        }

        private fun recordBlockedDomain(
            domain: String,
            reason: DnsDecisionReason
        ) {
            val normalized = DomainNameNormalizer.normalize(domain) ?: return
            synchronized(decisionEvents) {
                decisionEvents.add(
                    0,
                    DnsDecisionEvent(
                        id = decisionEventId.incrementAndGet().toLong(),
                        domain = normalized,
                        decision = DnsDecision.BLOCK,
                        reason = reason,
                        occurredAtMillis = System.currentTimeMillis()
                    )
                )
                if (decisionEvents.size > MAX_LOG_LINES) {
                    decisionEvents.removeAt(decisionEvents.lastIndex)
                }
                liveDecisionEventsFlow.value = decisionEvents.toList()
            }
        }

        private fun scheduleLogFlush() {
            logsDirty.set(true)
            if (!isUiForeground) return
            synchronized(flushLock) {
                if (logFlushJob?.isActive == true) return
                logFlushJob = flowFlushScope.launch {
                    do {
                        delay(FOREGROUND_LOG_FLUSH_MS)
                        if (!isUiForeground) return@launch
                        logsDirty.set(false)
                        flushLogsNow()
                    } while (logsDirty.get())
                    synchronized(flushLock) {
                        logFlushJob = null
                        if (logsDirty.get()) {
                            scheduleLogFlush()
                        }
                    }
                }
            }
        }

        private fun scheduleStatsFlush() {
            statsDirty.set(true)
            if (!isUiForeground) return
            synchronized(flushLock) {
                if (statsFlushJob?.isActive == true) return
                statsFlushJob = flowFlushScope.launch {
                    do {
                        delay(FOREGROUND_STATS_FLUSH_MS)
                        if (!isUiForeground) return@launch
                        statsDirty.set(false)
                        flushStatsNow()
                    } while (statsDirty.get())
                    synchronized(flushLock) {
                        statsFlushJob = null
                        if (statsDirty.get()) {
                            scheduleStatsFlush()
                        }
                    }
                }
            }
        }

        private fun flushLogsNow() {
            liveLogsFlow.value = synchronized(logList) {
                logList.toList()
            }
        }

        private fun flushStatsNow() {
            queryCountFlow.value = queryCounter.get()
            blockedAdsFlow.value = blockedAdsCounter.get()
            savedBytesFlow.value = savedBytesCounter.get()
        }

        fun parseDomainName(dnsPayload: ByteArray): String {
            val parsed = DnsMessageValidator.parseQuery(dnsPayload)
            return if (parsed is DnsQueryParseResult.Valid) {
                parsed.query.question.domainName ?: "Unknown"
            } else {
                "Unknown"
            }
        }

        fun isAdOrTracker(
            domain: String,
            policyAssembly: DomainPolicyAssembly = domainPolicy.snapshot()
        ): Boolean {
            val normalized = domain.lowercase().trim()
            if (normalized.isEmpty() || normalized == "unknown") return false

            val cacheKey = DomainPolicyCacheKey(normalized, policyAssembly)
            blockDecisionCache.get(cacheKey)?.let { return it }

            return policyAssembly.matcher.shouldBlock(normalized).also {
                blockDecisionCache.put(cacheKey, it)
            }
        }

        fun estimateSavedBytes(domain: String): Long {
            val d = domain.lowercase()

            return when {
                d.contains("video") || d.contains("vast") || d.contains("vpaid") ->
                    2_000 * 1024L

                d.contains("doubleclick") ||
                d.contains("googlesyndication") ||
                d.contains("googleads") ||
                d.contains("admob") ||
                d.contains("adservice") ||
                d.contains("adsystem") ||
                d.contains("amazon-adsystem") ->
                    500 * 1024L

                d.contains("analytics") ||
                d.contains("measurement") ||
                d.contains("app-measurement") ->
                    30 * 1024L

                d.contains("crashlytics") ||
                d.contains("crash") ->
                    15 * 1024L

                d.contains("telemetry") ->
                    40 * 1024L

                d.contains("tracker") ||
                d.contains("tracking") ||
                d.contains("adjust") ||
                d.contains("appsflyer") ->
                    80 * 1024L

                else ->
                    100 * 1024L
            }
        }

        // Standard, correct generation of synthetic DNS NXDOMAIN response packet
        fun buildNxDomainResponse(dnsPayload: ByteArray): ByteArray {
            val parsed = DnsMessageValidator.parseQuery(dnsPayload)
            require(parsed is DnsQueryParseResult.Valid) { "Cannot build NXDOMAIN for an invalid DNS query." }
            return DnsMessageValidator.buildNxDomainResponse(parsed.query)
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(serviceJob + Dispatchers.IO)
    private val domainPolicyReloadMutex = Mutex()

    private data class DnsStateSnapshot(
        val primary: String,
        val secondary: String?,
        val resolverGeneration: Int,
        val policyAssembly: DomainPolicyAssembly
    )

    private val dnsStateLock = Any()
    private var resolverGeneration = 0
    private val inFlightQueries = ConcurrentHashMap<DnsQueryKey, CompletableDeferred<ByteArray?>>()

    // Explicit, clean separation of VPN active running components from the general ServiceScope
    private var tunnelParentJob: Job? = null
    private var tunnelScope: CoroutineScope? = null

    // Robust local concurrency throttle to reduce background burst pressure on CPU and radio.
    private val querySemaphore = Semaphore(MAX_CONCURRENT_DNS_QUERIES)
    private val dohFailureBackoff = DohFailureBackoff()
    private val backgroundFailureLogLimiter = MonotonicIntervalGate(intervalMillis = 5_000)

    // One verified Public Suffix resolver owner per service lifecycle. The lazy is only touched when
    // a validated compiled blocklist actually needs parent-domain matching.
    private val publicSuffixResolverOwner by lazy {
        PublicSuffixResolverOwner.fromAssets(assets)
    }

    // The verified production blocklist is read once per service lifecycle and retained by its
    // ByteBuffer. A private filesDir/blocklists/active.bin remains an explicit local override.
    private val productionBlocklistLoader by lazy {
        ProductionBlocklistAssetLoader.fromAssets(assets)
    }

    @Volatile private var isVpnRunning = false

    private var upstreamDnsPrimary: String = "8.8.8.8"
    private var upstreamDnsSecondary: String? = "8.8.4.4"

    private fun updateResolverState(primary: String, secondary: String?) {
        synchronized(dnsStateLock) {
            upstreamDnsPrimary = primary
            upstreamDnsSecondary = secondary
            resolverGeneration++
            clearDnsStateLocked()
        }
    }

    private fun invalidatePolicyState() {
        synchronized(dnsStateLock) {
            clearDnsStateLocked()
        }
    }

    private suspend fun reloadDomainPolicy() {
        domainPolicyReloadMutex.withLock {
            reloadDomainPolicySnapshot()
        }
    }

    private suspend fun reloadDomainPolicySnapshot() {
        try {
            val storedRules = AppDatabase.getDatabase(this).dnsDao().getUserDomainRulesList()
            val ruleResolver = if (storedRules.any { it.includeSubdomains }) {
                publicSuffixResolverOwner.resolverOrNull()
            } else {
                null
            }
            var rejectedRuleCount = 0
            val userRules = storedRules.mapNotNull { entity ->
                val action = runCatching { DomainRuleAction.valueOf(entity.action) }.getOrNull()
                if (action == null) {
                    rejectedRuleCount++
                    return@mapNotNull null
                }
                when (
                    val validation = UserDomainRuleValidator.validate(
                        domain = entity.domain,
                        action = action,
                        includeSubdomains = entity.includeSubdomains,
                        resolver = ruleResolver
                    )
                ) {
                    is UserDomainRuleValidation.Valid -> validation.rule
                    is UserDomainRuleValidation.Invalid -> {
                        rejectedRuleCount++
                        null
                    }
                }
            }
            val assembly = RuntimeDomainPolicy.assemble(
                filesDirectory = filesDir,
                userRules = userRules,
                loadBundledBlocklist = productionBlocklistLoader::load,
                bundledSourceMetadata = productionBlocklistLoader.sourceMetadata,
                registrableDomainResolverProvider = {
                    publicSuffixResolverOwner.resolverOrNull()
                }
            )
            withContext(Dispatchers.Main.immediate) {
                domainPolicy.install(assembly) {
                    invalidatePolicyState()
                }
                if (rejectedRuleCount > 0) {
                    addLog("[網域規則] 有 $rejectedRuleCount 條無效或無法通過 PSL 驗證的規則未套用。")
                }
                rulePolicyStatusFlow.value = assembly.displayStatus.copy(
                    publicSuffixStatus = if (assembly.displayStatus.source == RuleBlocklistSource.BUILT_IN) {
                        PublicSuffixResolverStatus.NotLoaded
                    } else {
                        publicSuffixResolverOwner.status()
                    },
                    reloadError = null
                )
            }
        } catch (exception: CancellationException) {
            throw exception
        } catch (exception: Exception) {
            val reason = exception.message?.takeIf(String::isNotBlank)
                ?: exception.javaClass.simpleName
            Log.e(TAG, "Failed to reload domain policy", exception)
            withContext(Dispatchers.Main.immediate) {
                rulePolicyStatusFlow.value = rulePolicyStatusFlow.value.copy(reloadError = reason)
            }
            addLog("[攔截規則] 重新載入失敗，保留目前規則：$reason")
            return
        }

        addLog(DomainPolicyDiagnostics.message(rulePolicyStatusFlow.value))
    }
    private fun clearDnsStateLocked() {
        synchronized(dnsCache) { dnsCache.evictAll() }
        inFlightQueries.clear()
        blockDecisionCache.evictAll()
    }

    private fun snapshotDnsState(): DnsStateSnapshot = synchronized(dnsStateLock) {
        DnsStateSnapshot(
            primary = upstreamDnsPrimary,
            secondary = upstreamDnsSecondary,
            resolverGeneration = resolverGeneration,
            policyAssembly = domainPolicy.snapshot()
        )
    }

    private fun isCurrentDnsState(state: DnsStateSnapshot): Boolean = synchronized(dnsStateLock) {
        resolverGeneration == state.resolverGeneration &&
            domainPolicy.snapshot() === state.policyAssembly
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                addLog("Starting service command received")
                startVpn()
            }
            ACTION_STOP -> {
                addLog("Stopping service command received")
                stopVpn()
                stopSelf()
            }
            ACTION_RESTART -> {
                addLog("Restarting service command received")
                restartTunnel()
            }
            ACTION_UPDATE_DNS -> {
                val primary = intent.getStringExtra("primary") ?: "8.8.8.8"
                val secondary = intent.getStringExtra("secondary")
                val dnsName = intent.getStringExtra("dnsName") ?: "Google DNS"
                updateResolverState(primary, secondary)
                activeDnsFlow.value = "$dnsName ($primary)"
                addLog("[DNS 變更同步] 已即時套用新 DNS 設定：$dnsName ($primary)")
            }
            ACTION_CLEAR_LOGS -> {
                clearLogs()
            }
            ACTION_RELOAD_DOMAIN_POLICY -> {
                serviceScope.launch { reloadDomainPolicy() }
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        serviceJob.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        addLog("VPN connection revoked by system settings")
        stopVpn()
        stopSelf()
        super.onRevoke()
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= MEMORY_TRIM_CLEAR_CACHE_LEVEL) {
            clearMemoryCache()
        }
    }

    override fun onLowMemory() {
        super.onLowMemory()
        clearMemoryCache()
    }

    private fun startVpn() {
        if (isVpnRunning) return

        val notification = createNotification("DNS Shield VPN 正在啟動中...")
        if (android.os.Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        // Start active background tunnel operations under tunnelParentJob & separate tunnelScope
        val activeJob = SupervisorJob(serviceJob)
        tunnelParentJob = activeJob
        val activeTunnelScope = CoroutineScope(activeJob + Dispatchers.IO)
        tunnelScope = activeTunnelScope

        activeTunnelScope.launch {
            try {
                reloadDomainPolicy()

                // Read active DNS from Room Database
                val db = AppDatabase.getDatabase(this@DnsVpnService)
                val activeServer = db.dnsDao().getActiveDnsServer()
                val primary = activeServer?.primaryIp ?: "8.8.8.8"
                val secondary = activeServer?.secondaryIp
                updateResolverState(primary, secondary)
                val dnsName = activeServer?.name ?: "Google DNS"
                activeDnsFlow.value = "$dnsName ($primary)"

                addLog("Database loaded. Upstream DNS: $dnsName ($primary)")

                // Read list of bypassed application packages from database
                val bypassedList = db.dnsDao().getBypassedAppsList()
                addLog("Loaded ${bypassedList.size} apps to exempt/bypass DNS VPN")

                // Configure VPN interface
                val builder = Builder()
                    .setSession("DNS Shield")
                    // The default non-blocking TUN descriptor busy-spins when no packet is ready.
                    .setBlocking(true)
                    .addAddress(VPN_IP, 32)
                    .addRoute(DUMMY_DNS_IP, 32) // Route dummy DNS requests to TUN interface
                    .addDnsServer(DUMMY_DNS_IP) // Set dummy IP as DNS server

                // Add disallowed applications (split tunneling)
                for (app in bypassedList) {
                    try {
                        builder.addDisallowedApplication(app.packageName)
                        addLog("Exempted app: ${app.appName} (${app.packageName})")
                    } catch (e: PackageManager.NameNotFoundException) {
                        Log.w(TAG, "Exempted app package not found on device: ${app.packageName}")
                    } catch (e: Exception) {
                        Log.e(TAG, "Error adding disallowed package: ${app.packageName}", e)
                    }
                }

                val establishedFd = builder.establish()
                if (establishedFd == null) {
                    addLog("Error: Failed to establish VPN interface (null)")
                    stopVpn()
                    stopSelf()
                    return@launch
                }

                vpnInterface = establishedFd
                // Rules can change while the VPN is being established; load them again before handling packets.
                reloadDomainPolicy()
                isVpnRunning = true
                isRunningFlow.value = true
                addLog("[防護成功] 安全 DNS 防護已成功啟動並建立通道。")

                // Update notification text to active state
                val activeNotification = createNotification("DNS Shield VPN 正在運作中")
                val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                manager.notify(NOTIFICATION_ID, activeNotification)

                addLog("VPN Interface Established. Reading packets...")
                runTunnel()

            } catch (e: Exception) {
                addLog("VPN crashed: ${e.message}")
                stopVpn()
                stopSelf()
            }
        }
    }

    private fun runTunnel() {
        vpnInterface?.let { pfd ->
            val inputStream = FileInputStream(pfd.fileDescriptor)
            val outputStream = FileOutputStream(pfd.fileDescriptor)

            val buffer = ByteArray(4096)
            try {
                while (isVpnRunning) {
                    val readBytes = inputStream.read(buffer)
                    if (readBytes > 0) {
                        handlePacket(buffer, readBytes, outputStream)
                    } else if (readBytes < 0) {
                        break
                    }
                }
            } catch (e: IOException) {
                addLog("Tunnel read error: ${e.message}")
            } finally {
                try {
                    inputStream.close()
                } catch (e: Exception) {}
                try {
                    outputStream.close()
                } catch (e: Exception) {}
            }
        }
    }

    private fun handlePacket(packet: ByteArray, length: Int, outputStream: FileOutputStream) {
        when (val parsed = DnsIpv4UdpQueryParser.parse(packet, length)) {
            is Ipv4UdpDnsParseResult.Query -> {
                val dnsPacket = parsed.packet
                val activeScope = tunnelScope
                if (activeScope != null && activeScope.isActive) {
                    activeScope.launch {
                        try {
                            forwardDnsQuery(
                                dnsPacket.payload,
                                dnsPacket.query,
                                dnsPacket.sourceIp,
                                dnsPacket.destinationIp,
                                dnsPacket.sourcePort,
                                outputStream
                            )
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed in DNS query coroutine", e)
                        }
                    }
                }
            }
            Ipv4UdpDnsParseResult.NotDns -> return
            is Ipv4UdpDnsParseResult.Rejected -> {
                parsed.dnsErrorResponse?.let { response ->
                    sendResponsePacket(
                        responseData = response.dnsPayload,
                        clientIp = response.clientIp,
                        mockDnsIp = response.resolverIp,
                        clientPort = response.clientPort,
                        outputStream = outputStream
                    )
                }
            }
        }
    }

    private suspend fun performDohLookup(
        dohUrl: String,
        query: ParsedDnsQuery
    ): ByteArray? {
        val mediaType = "application/dns-message".toMediaType()
        val requestBody = DnsMessageValidator.prepareUpstreamQuery(query).toRequestBody(mediaType)

        val request = Request.Builder()
            .url(dohUrl)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .post(requestBody)
            .build()

        val client = getOkHttpClient()
        val call = client.newCall(request)

        return suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation {
                try {
                    call.cancel()
                } catch (e: Exception) {
                    Log.e(TAG, "Error cancelling call", e)
                }
            }

            call.enqueue(object : okhttp3.Callback {
                override fun onFailure(call: okhttp3.Call, e: java.io.IOException) {
                    if (continuation.isActive) {
                        logDnsTransportFailure("DoH resolution failed for $dohUrl", e)
                        continuation.resume(null)
                    }
                }

                override fun onResponse(call: okhttp3.Call, response: okhttp3.Response) {
                    try {
                        if (continuation.isActive) {
                            if (response.isSuccessful) {
                                val body = response.body
                                val bytes = DnsDohResponseValidator.readValidatedBody(
                                    contentType = response.header("Content-Type"),
                                    contentLength = body.contentLength(),
                                    stream = body.byteStream(),
                                    query = query
                                )
                                continuation.resume(bytes)
                            } else {
                                logDnsTransportFailure("DoH resolution error: HTTP ${response.code} for $dohUrl")
                                continuation.resume(null)
                            }
                        } else {
                            response.close()
                        }
                    } catch (e: Exception) {
                        logDnsTransportFailure("Failed reading DoH body bytes", e)
                        if (continuation.isActive) {
                            continuation.resume(null)
                        }
                    } finally {
                        try {
                            response.close()
                        } catch (e: Exception) {}
                    }
                }
            })
        }
    }

    private fun sendResponsePacket(
        responseData: ByteArray,
        clientIp: ByteArray,
        mockDnsIp: ByteArray,
        clientPort: Int,
        outputStream: FileOutputStream,
        transactionIdSource: ByteArray? = null
    ) {
        val responseIpPacket = DnsResponsePacketBuilder.build(
            srcIp = mockDnsIp, // 10.0.0.1
            dstIp = clientIp,   // Client IP
            srcPort = 53,
            dstPort = clientPort,
            payload = responseData,
            transactionIdSource = transactionIdSource
        )

        try {
            synchronized(outputStream) {
                outputStream.write(responseIpPacket)
                outputStream.flush()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error writing packet to TUN output stream", e)
        }
    }

    private suspend fun forwardDnsQuery(
        dnsPayload: ByteArray,
        query: ParsedDnsQuery,
        clientIp: ByteArray,
        mockDnsIp: ByteArray,
        clientPort: Int,
        outputStream: FileOutputStream
    ) {
        val dnsState = snapshotDnsState()
        val queryKey = DnsQueryKey(
            bytes = dnsPayload,
            resolverGeneration = dnsState.resolverGeneration,
            policyAssembly = dnsState.policyAssembly
        )

        // 1. Return known-good cached responses before doing domain parsing or block matching.
        val cachedResponse = getCache(queryKey)
        if (cachedResponse != null) {
            sendResponsePacket(
                cachedResponse,
                clientIp,
                mockDnsIp,
                clientPort,
                outputStream,
                transactionIdSource = dnsPayload
            )

            recordResolvedQuery()

            addDnsQueryLog {
                val domain = query.question.domainName ?: "Unknown"
                "⚡ [快取解析] [ID=${formatTxId(dnsPayload)}]: $domain (記憶體命中, ${cachedResponse.size} bytes)"
            }
            return
        }

        val domain = query.question.domainName ?: "Unknown"

        // 2. Check if ad domain / tracker - BLOCK IMMEDIATELY with genuine NXDOMAIN synthesis
        val isAd = isAdOrTracker(domain, dnsState.policyAssembly)
        if (isAd) {
            val blockedResponse = DnsMessageValidator.buildNxDomainResponse(query)
            sendResponsePacket(blockedResponse, clientIp, mockDnsIp, clientPort, outputStream)

            val savedInBytes = estimateSavedBytes(domain)
            recordBlockedQuery(savedInBytes)
            val reason = if (
                dnsState.policyAssembly.userRuleMatcher.decisionFor(domain) == DomainRuleAction.BLOCK
            ) {
                DnsDecisionReason.USER_RULE
            } else {
                DnsDecisionReason.PROTECTION_LIST
            }
            recordBlockedDomain(domain, reason)

            addDnsQueryLog {
                "🛡️ [真正攔截] $domain -> NXDOMAIN"
            }
            return
        }

        // 3. Coalesce only allowed cache misses. One leader consumes an upstream permit.
        val leaderResult = CompletableDeferred<ByteArray?>()
        val existingResult = inFlightQueries.putIfAbsent(queryKey, leaderResult)
        val sharedResponse = if (existingResult != null) {
            existingResult.await()
        } else {
            try {
                val response = querySemaphore.withPermit {
                    resolveUpstreamQuery(dnsPayload, query, domain, dnsState)
                }
                val validatedResponse = response?.takeIf {
                    DnsMessageValidator.isValidResponse(it, query)
                }
                if (validatedResponse != null &&
                    isCurrentDnsState(dnsState)
                ) {
                    putCache(queryKey, validatedResponse, query)
                }
                leaderResult.complete(validatedResponse)
                validatedResponse
            } catch (e: CancellationException) {
                leaderResult.cancel(e)
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "DNS resolution leader failed", e)
                leaderResult.complete(null)
                null
            } finally {
                inFlightQueries.remove(queryKey, leaderResult)
            }
        }

        // 4. Every client packet is stamped with its own transaction ID while copying the payload.
        if (sharedResponse != null) {
            sendResponsePacket(
                sharedResponse,
                clientIp,
                mockDnsIp,
                clientPort,
                outputStream,
                transactionIdSource = dnsPayload
            )

            recordResolvedQuery()

            addDnsQueryLog {
                "✓ 解析成功 [ID=${formatTxId(dnsPayload)}]: $domain (${sharedResponse.size} bytes)"
            }
        } else {
            sendResponsePacket(
                DnsMessageValidator.buildServFailResponse(query),
                clientIp,
                mockDnsIp,
                clientPort,
                outputStream
            )
            if (isUiForeground || backgroundFailureLogLimiter.tryAcquire()) {
                addDnsQueryLog(important = true) {
                    "✗ 請求失敗 [ID=${formatTxId(dnsPayload)}]: $domain 伺服器逾時或無回應"
                }
            }
        }
    }

    private suspend fun resolveUpstreamQuery(
        dnsPayload: ByteArray,
        query: ParsedDnsQuery,
        domain: String,
        dnsState: DnsStateSnapshot
    ): ByteArray? {
        var responseData: ByteArray? = null
        val primaryDoHUrl = getDoHUrl(dnsState.primary)

        if (primaryDoHUrl != null && dohFailureBackoff.tryAcquire(primaryDoHUrl)) {
            try {
                responseData = performDohLookup(primaryDoHUrl, query)
            } catch (e: CancellationException) {
                dohFailureBackoff.cancelAttempt(primaryDoHUrl)
                throw e
            } catch (e: Exception) {
                dohFailureBackoff.recordFailure(primaryDoHUrl)
                throw e
            }

            if (responseData != null) {
                dohFailureBackoff.recordSuccess(primaryDoHUrl)
                addDnsQueryLog {
                    "🌐 [DoH 解析] [ID=${formatTxId(dnsPayload)}]: 透過安全 HTTPS 連線成功解析 $domain"
                }
            } else {
                dohFailureBackoff.recordFailure(primaryDoHUrl)
            }
        }

        // Fallback to UDP if DoH is not applicable or failed.
        if (responseData == null) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                protect(socket)

                val primaryAddress = InetAddress.getByName(dnsState.primary)
                responseData = DnsUdpUpstreamClient.query(
                    socket, query, primaryAddress, port = BuildConfig.DNS_UPSTREAM_PORT
                )

                if (responseData == null && dnsState.secondary != null) {
                    val secondaryAddress = InetAddress.getByName(dnsState.secondary)
                    responseData = DnsUdpUpstreamClient.query(
                        socket, query, secondaryAddress, port = BuildConfig.DNS_UPSTREAM_PORT
                    )
                }
            } catch (e: Exception) {
                logDnsTransportFailure("Standard UDP resolution fallback exception", e)
            } finally {
                socket?.close()
            }
        }
        return responseData?.takeIf { DnsMessageValidator.isValidResponse(it, query) }
    }

    private fun formatTxId(dnsPayload: ByteArray): String {
        return if (dnsPayload.size >= 2) {
            String.format("0x%02X%02X", dnsPayload[0], dnsPayload[1])
        } else {
            "Unknown"
        }
    }

    // Gracefully and synchronously shutdown tunnel resources to prevent leakage
    private fun closeTunnelResources() {
        isVpnRunning = false
        isRunningFlow.value = false
        rulePolicyStatusFlow.value = RulePolicyStatus.NotLoaded

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing vpnInterface descriptor", e)
        }
        vpnInterface = null

        tunnelParentJob?.cancel()
        tunnelParentJob = null
        tunnelScope = null
    }

    // Gracefully and asynchronously join tunnel routines before starting a new one
    private suspend fun closeTunnelResourcesAndJoin() {
        isVpnRunning = false
        isRunningFlow.value = false
        rulePolicyStatusFlow.value = RulePolicyStatus.NotLoaded

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing vpnInterface descriptor", e)
        }
        vpnInterface = null

        try {
            tunnelParentJob?.cancelAndJoin()
        } catch (e: Exception) {
            Log.e(TAG, "Exception cancelling tunnelParentJob during shutdown", e)
        }
        tunnelParentJob = null
        tunnelScope = null
    }

    private fun restartTunnel() {
        // Run on Main so state changes and logs settle smoothly
        serviceScope.launch(Dispatchers.Main) {
            addLog("[安全防護] 正在重新啟動 DNS 隧道以套用新名單...")

            // 1. Mark as not running & notify
            isRunningFlow.value = false

            // 2. Tear down everything and wait safely
            closeTunnelResourcesAndJoin()

            // 3. Delay gracefully to allow system teardown to settle perfectly
            delay(400)

            // 4. Start tunnel again
            startVpn()
        }
    }

    private fun stopVpn() {
        addLog("正在關閉安全 DNS 防護隧道並釋放資源...")

        closeTunnelResources()

        // Stop foreground and remove the banner notification
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping foreground service", e)
        }

        Log.i(TAG, "VPN stopped completely")
    }

    private fun createNotification(content: String): Notification {
        val stopIntent = Intent(this, DnsVpnService::class.java).apply {
            action = ACTION_STOP
        }

        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }

        val stopPendingIntent = PendingIntent.getService(this, 1, stopIntent, flags)

        val mainIntent = Intent(this, MainActivity::class.java)
        val mainPendingIntent = PendingIntent.getActivity(this, 0, mainIntent, flags)

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock) // Standard lock icon
            .setContentTitle("DNS Shield VPN")
            .setContentText(content)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(mainPendingIntent)
            .addAction(android.R.drawable.ic_media_pause, "停止服務", stopPendingIntent)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "DNS Shield ",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "通知使用者 DNS VPN 正在運作中"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }
}
