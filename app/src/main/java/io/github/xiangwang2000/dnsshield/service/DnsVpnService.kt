package io.github.xiangwang2000.dnsshield.service

import io.github.xiangwang2000.dnsshield.BuildConfig

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import io.github.xiangwang2000.dnsshield.MainActivity
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
import io.github.xiangwang2000.dnsshield.data.DnsServer
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import android.util.LruCache
import okhttp3.OkHttpClient
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
        internal const val NOTIFICATION_ID = 5543
        internal fun createVpnNotification(context: Context, content: String): Notification {
            val stopIntent = Intent(context, DnsVpnService::class.java).apply {
                action = ACTION_STOP
            }

            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            } else {
                PendingIntent.FLAG_UPDATE_CURRENT
            }

            val stopPendingIntent = PendingIntent.getService(context, 1, stopIntent, flags)

            val mainIntent = Intent(context, MainActivity::class.java)
            val mainPendingIntent = PendingIntent.getActivity(context, 0, mainIntent, flags)

            return NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_lock_lock) // Standard lock icon
                .setContentTitle("DNS Shield VPN")
                .setContentText(content)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setContentIntent(mainPendingIntent)
                .addAction(android.R.drawable.ic_media_pause, "停止服務", stopPendingIntent)
                .build()
        }

        internal fun createVpnNotificationChannel(context: Context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    "DNS Shield ",
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = "通知使用者 DNS VPN 正在運作中"
                }
                val manager = context.getSystemService(NotificationManager::class.java)
                manager?.createNotificationChannel(channel)
            }
        }

        private const val MAX_CONCURRENT_DNS_QUERIES = 24
        private const val MAX_COALESCED_DNS_QUERY_WAITERS = 8
        private const val MAX_LOG_LINES = 100
        private const val FOREGROUND_LOG_FLUSH_MS = 300L
        private const val FOREGROUND_STATS_FLUSH_MS = 500L
        private const val MEMORY_TRIM_CLEAR_CACHE_LEVEL = 60
        private const val NETWORK_CHANGE_DEBOUNCE_MS = 500L
        private const val NETWORK_CHANGE_POLL_MS = 25L

        const val VPN_IP = "10.0.0.2"
        const val DUMMY_DNS_IP = "10.0.0.1"

        // Publish one lifecycle state for the UI and service notification.
        val lifecycleStateFlow = MutableStateFlow(VpnLifecycleState.STOPPED)
        internal val diagnosticsFlow = MutableStateFlow(DnsDiagnosticsSnapshot())
        val activeDnsFlow = MutableStateFlow("None")
        val dnsTransportStatusFlow = MutableStateFlow("尚無上游查詢")
        val liveLogsFlow = MutableStateFlow<List<String>>(emptyList())
        private val plaintextFallbackFence = DnsPlaintextFallbackFence()

        fun setPlaintextFallbackAllowed(resolverId: Int, allowed: Boolean) {
            plaintextFallbackFence.setAllowed(resolverId, allowed)
        }
        val liveDecisionEventsFlow = MutableStateFlow<List<DnsDecisionEvent>>(emptyList())
        val rulePolicyStatusFlow = MutableStateFlow(RulePolicyStatus.NotLoaded)

        private val diagnosticMetrics = DnsDiagnosticMetrics()

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
            private val underlyingNetworkGeneration: Long,
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
                if (underlyingNetworkGeneration != other.underlyingNetworkGeneration) return false
                if (policyAssembly !== other.policyAssembly) return false
                if (bytes.size != other.bytes.size) return false
                for (i in 2 until bytes.size) {
                    if (bytes[i] != other.bytes[i]) return false
                }
                return true
            }

            override fun hashCode(): Int = cachedHashCode

            private fun calculateHashCode(): Int {
                var result = 31 * resolverGeneration + underlyingNetworkGeneration.hashCode()
                result = 31 * result + System.identityHashCode(policyAssembly)
                for (i in 2 until bytes.size) {
                    result = 31 * result + bytes[i]
                }
                return result
            }

            fun copyForStorage() = DnsQueryKey(
                bytes = bytes.copyOf(),
                resolverGeneration = resolverGeneration,
                underlyingNetworkGeneration = underlyingNetworkGeneration,
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
                    .callTimeout(DnsRequestDeadline.DEFAULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
                    .connectionPool(ConnectionPool(5, 5, java.util.concurrent.TimeUnit.MINUTES))
                    .build().also { okHttpClientInstance = it }
            }
        }

        private fun resetOkHttpClientForUnderlyingNetworkChange() {
            synchronized(this) {
                val client = okHttpClientInstance ?: return
                client.connectionPool.evictAll()
                okHttpClientInstance = null
            }
        }

        fun getDoHUrl(ip: String): String? {
            return DohEndpointConfiguration.defaultUrlForIp(ip)
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
            diagnosticMetrics.reset()
            synchronized(decisionEvents) {
                decisionEvents.clear()
                liveDecisionEventsFlow.value = emptyList()
            }
            if (isUiForeground) {
                flushStatsNow()
            }
        }

        private fun beginDnsRequest(receivedAtNanos: Long): DnsDiagnosticMetrics.Request =
            diagnosticMetrics.begin(receivedAtNanos).also { scheduleStatsFlush() }

        private fun completeDnsRequest(
            request: DnsDiagnosticMetrics.Request,
            outcome: DnsClientTerminalOutcome,
            savedBytes: Long = 0L
        ) {
            if (diagnosticMetrics.complete(request, outcome, savedBytes = savedBytes)) {
                scheduleStatsFlush()
            }
        }

        private fun recordCacheHit(request: DnsDiagnosticMetrics.Request) {
            diagnosticMetrics.recordCacheHit(request)
            scheduleStatsFlush()
        }

        private fun recordCoalesced(request: DnsDiagnosticMetrics.Request) {
            diagnosticMetrics.recordCoalesced(request)
            scheduleStatsFlush()
        }

        private fun recordOverload(request: DnsDiagnosticMetrics.Request) {
            diagnosticMetrics.recordOverload(request)
            scheduleStatsFlush()
        }

        private fun recordTransportAttempt(
            request: DnsDiagnosticMetrics.Request,
            transport: DnsUpstreamTransport
        ) {
            diagnosticMetrics.recordTransportAttempt(request, transport)
            scheduleStatsFlush()
        }

        private fun recordFallbackAttempt(request: DnsDiagnosticMetrics.Request) {
            diagnosticMetrics.recordFallbackAttempt(request)
            scheduleStatsFlush()
        }

        private fun recordUdpRetryAttempt(request: DnsDiagnosticMetrics.Request) {
            diagnosticMetrics.recordUdpRetryAttempt(request)
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
            diagnosticsFlow.value = diagnosticMetrics.snapshot()
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
    private val lifecycleCommands = Channel<LifecycleCommand>(Channel.UNLIMITED)
    private val lifecycleRequests = VpnLifecycleRequestTracker()
    private val userIntentStore by lazy {
        VpnUserIntentStore(
            getSharedPreferences(VPN_SERVICE_PREFERENCES, Context.MODE_PRIVATE)
        )
    }
    private var latestLifecycleStartId = 0

    private fun systemAlwaysOnEnabled(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isAlwaysOn

    private sealed class LifecycleCommand {
        data class Start(val startId: Int, val requestGeneration: Long) : LifecycleCommand()
        data class Stop(val startId: Int) : LifecycleCommand()
        data class Restart(val startId: Int, val requestGeneration: Long) : LifecycleCommand()
        data class UpdateDns(val startId: Int, val resolverId: Int) : LifecycleCommand()
        data class ClearLogs(val startId: Int) : LifecycleCommand()
        data class TunnelEnded(
            val generation: Long,
            val descriptor: ParcelFileDescriptor,
            val failure: String?
        ) : LifecycleCommand()
    }
    private val domainPolicyReloadMutex = Mutex()

    private data class DnsStateSnapshot(
        val server: DnsServer,
        val resolverGeneration: Int,
        val underlyingNetworkGeneration: Long,
        val policyAssembly: DomainPolicyAssembly
    )

    private data class NetworkCallbackRegistration(
        val token: Long,
        val manager: ConnectivityManager,
        val underlyingCallback: ConnectivityManager.NetworkCallback,
        val defaultCallback: ConnectivityManager.NetworkCallback,
        val bestMatchingCallback: ConnectivityManager.NetworkCallback?
    ) {
        val callbacks: List<ConnectivityManager.NetworkCallback>
            get() = listOfNotNull(underlyingCallback, defaultCallback, bestMatchingCallback)
    }

    private val dnsStateLock = Any()
    private var resolverGeneration = 0
    private var underlyingNetworkGeneration = 0L
    private var underlyingNetworkChangePending = false
    private val queryAdmission = BoundedDnsQueryAdmission<DnsQueryKey>(
        maxUniqueKeys = MAX_CONCURRENT_DNS_QUERIES,
        maxWaitersPerKey = MAX_COALESCED_DNS_QUERY_WAITERS
    )
    private val underlyingNetworkReducer = UnderlyingNetworkStateReducer()
    private val networkRecoveryTracker = UnderlyingNetworkRecoveryTracker()
    private val underlyingNetworkEventLock = Any()
    private val networkCallbackLock = Any()
    @Volatile private var networkCallbackToken = 0L
    @Volatile private var networkCallbackRegistration: NetworkCallbackRegistration? = null
    private var networkStatusDebounceJob: Job? = null
    private val activeDnsLeaders = ConcurrentHashMap<Job, DnsStateSnapshot>()

    // Explicit, clean separation of VPN active running components from the general ServiceScope
    private var tunnelParentJob: Job? = null
    private var tunnelScope: CoroutineScope? = null
    private val tcpRuntimeLock = Any()
    private var tcpRuntime: NativeDnsTcpRuntime? = null
    @Volatile private var tunnelGeneration = 0L

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

    private var upstreamDnsServer = DnsServer(
        name = "Google DNS",
        primaryIp = "8.8.8.8",
        secondaryIp = "8.8.4.4"
    )

    private fun updateResolverState(server: DnsServer) {
        synchronized(dnsStateLock) {
            upstreamDnsServer = server
            resolverGeneration++
            clearDnsStateLocked()
        }
        dnsTransportStatusFlow.value = "設定已更新，等待下一次查詢"
    }

    private fun invalidatePolicyState() {
        synchronized(dnsStateLock) {
            clearDnsStateLocked()
        }
    }

    private suspend fun reloadDomainPolicy(requestGeneration: Long? = null) {
        domainPolicyReloadMutex.withLock {
            reloadDomainPolicySnapshot(requestGeneration)
        }
    }

    private suspend fun reloadDomainPolicySnapshot(requestGeneration: Long?) {
        try {
            val (assembly, rejectedRuleCount) = withContext(Dispatchers.IO) {
                val storedRules = AppDatabase.getDatabase(this@DnsVpnService).dnsDao().getUserDomainRulesList()
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
                assembly to rejectedRuleCount
            }
            if (requestGeneration != null && !lifecycleRequests.isCurrent(requestGeneration)) return
            withContext(Dispatchers.Main.immediate) {
                if (requestGeneration != null && !lifecycleRequests.isCurrent(requestGeneration)) return@withContext
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
            if (requestGeneration != null && !lifecycleRequests.isCurrent(requestGeneration)) return
        } catch (exception: CancellationException) {
            throw exception
        } catch (exception: Exception) {
            if (requestGeneration != null && !lifecycleRequests.isCurrent(requestGeneration)) return
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
        clearDnsAnswerCacheLocked()
        blockDecisionCache.evictAll()
    }

    private fun clearDnsAnswerCacheLocked() {
        synchronized(dnsCache) { dnsCache.evictAll() }
    }

    private fun snapshotDnsState(): DnsStateSnapshot = synchronized(dnsStateLock) {
        DnsStateSnapshot(
            server = upstreamDnsServer,
            resolverGeneration = resolverGeneration,
            underlyingNetworkGeneration = underlyingNetworkGeneration,
            policyAssembly = domainPolicy.snapshot()
        )
    }

    private fun isCurrentDnsState(state: DnsStateSnapshot): Boolean = synchronized(dnsStateLock) {
        isCurrentDnsStateLocked(state)
    }

    private fun isCurrentDnsStateLocked(state: DnsStateSnapshot): Boolean {
        return resolverGeneration == state.resolverGeneration &&
            underlyingNetworkGeneration == state.underlyingNetworkGeneration &&
            domainPolicy.snapshot() === state.policyAssembly
    }

    private fun registerUnderlyingNetworkCallback() {
        val manager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        if (manager == null) {
            addLog("[網路狀態] 無法監看網路變更；DNS 伺服器設定維持不變。")
            return
        }

        val registration = synchronized(networkCallbackLock) {
            if (networkCallbackRegistration != null) return
            underlyingNetworkReducer.clear()
            networkRecoveryTracker.clear()
            val token = ++networkCallbackToken
            val underlyingCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onCapabilitiesChanged(
                    network: Network,
                    networkCapabilities: NetworkCapabilities
                ) {
                    onUnderlyingNetworkEvent(token, networkFacts(network, networkCapabilities))
                }

                override fun onLost(network: Network) {
                    onUnderlyingNetworkEvent(
                        token,
                        UnderlyingNetworkFacts(
                            networkId = network.networkHandle,
                            isVpn = false,
                            hasInternet = false,
                            isValidated = false,
                            hasCaptivePortal = false,
                            lost = true
                        )
                    )
                }
            }

            var activeDefaultNetwork: Network? = null
            val defaultNetworkLock = Any()
            val defaultCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    synchronized(defaultNetworkLock) { activeDefaultNetwork = network }
                }

                override fun onCapabilitiesChanged(
                    network: Network,
                    networkCapabilities: NetworkCapabilities
                ) {
                    synchronized(defaultNetworkLock) { activeDefaultNetwork = network }
                    val facts = networkFacts(network, networkCapabilities)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        if (!facts.isVpn) {
                            onUnderlyingNetworkChange(token) { reducer ->
                                reducer.selectDefaultNetwork(network.networkHandle)
                            }
                        }
                    } else if (facts.isVpn) {
                        onUnderlyingNetworkChange(token) { reducer ->
                            reducer.selectDefaultNetworkByTransportMask(facts.transportMask)
                        }
                    } else {
                        onUnderlyingNetworkChange(token) { reducer ->
                            reducer.selectDefaultNetwork(network.networkHandle)
                        }
                    }
                }

                override fun onLost(network: Network) {
                    val wasActiveDefault = synchronized(defaultNetworkLock) {
                        if (activeDefaultNetwork != network) {
                            false
                        } else {
                            activeDefaultNetwork = null
                            true
                        }
                    }
                    if (wasActiveDefault && Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
                        onUnderlyingNetworkChange(token) { reducer ->
                            reducer.selectDefaultNetwork(null)
                        }
                    }
                }
            }

            val bestMatchingCallback = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        selectBestMatchingNetwork(token, network.networkHandle)
                    }

                    override fun onCapabilitiesChanged(
                        network: Network,
                        networkCapabilities: NetworkCapabilities
                    ) {
                        selectBestMatchingNetwork(token, network.networkHandle)
                    }

                    override fun onLost(network: Network) {
                        onUnderlyingNetworkChange(token) { reducer ->
                            reducer.clearSelectedDefaultNetwork(network.networkHandle)
                        }
                    }
                }
            } else {
                null
            }
            NetworkCallbackRegistration(
                token,
                manager,
                underlyingCallback,
                defaultCallback,
                bestMatchingCallback
            ).also {
                networkCallbackRegistration = it
            }
        }

        val initialState = underlyingNetworkReducer.snapshot()
        scheduleNetworkStatusUpdate(
            token = registration.token,
            state = initialState,
            generation = currentUnderlyingNetworkGeneration(),
            networkChanged = false
        )

        try {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            manager.registerNetworkCallback(request, registration.underlyingCallback)
            manager.registerDefaultNetworkCallback(registration.defaultCallback)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                registration.bestMatchingCallback?.let { callback ->
                    manager.registerBestMatchingNetworkCallback(request, callback, Handler(Looper.getMainLooper()))
                }
            }
        } catch (exception: Exception) {
            unregisterUnderlyingNetworkCallback()
            Log.w(TAG, "Unable to register the underlying network callback", exception)
            addLog("[網路狀態] 無法監看網路變更；DNS 伺服器設定維持不變。")
        }
    }

    private fun networkFacts(
        network: Network,
        capabilities: NetworkCapabilities?
    ): UnderlyingNetworkFacts {
        val transportMask = capabilities?.let(::physicalTransportMask) ?: 0
        val isVpn = capabilities?.let {
            it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                !it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        } ?: false

        return UnderlyingNetworkFacts(
            networkId = network.networkHandle,
            isVpn = isVpn,
            hasInternet = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ?: true,
            isValidated = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true,
            hasCaptivePortal = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true,
            transportMask = transportMask
        )
    }

    private fun physicalTransportMask(capabilities: NetworkCapabilities): Int {
        var mask = 0
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) mask = mask or 1
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) mask = mask or 2
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) mask = mask or 4
        return mask
    }

    private fun onUnderlyingNetworkEvent(token: Long, facts: UnderlyingNetworkFacts) {
        onUnderlyingNetworkChange(token) { reducer -> reducer.update(facts) }
    }

    private fun selectBestMatchingNetwork(token: Long, networkId: Long) {
        onUnderlyingNetworkChange(token) { reducer -> reducer.selectDefaultNetwork(networkId) }
    }

    private fun onUnderlyingNetworkChange(
        token: Long,
        update: (UnderlyingNetworkStateReducer) -> UnderlyingNetworkTransition?
    ) {
        val transition: UnderlyingNetworkTransition
        val generation: Long
        synchronized(underlyingNetworkEventLock) {
            if (
                token != networkCallbackToken ||
                networkCallbackRegistration?.token != token ||
                !isVpnRunning
            ) return

            transition = update(underlyingNetworkReducer) ?: return
            networkRecoveryTracker.observe(transition, System.nanoTime())
            generation = synchronized(dnsStateLock) {
                underlyingNetworkGeneration++
                underlyingNetworkChangePending = true
                clearDnsAnswerCacheLocked()
                underlyingNetworkGeneration
            }
            dohFailureBackoff.resetForGeneration(generation)
            activeDnsLeaders.forEach { (job, state) ->
                if (state.underlyingNetworkGeneration != generation) {
                    job.cancel(CancellationException("Underlying network changed"))
                }
            }
        }
        scheduleNetworkStatusUpdate(
            token = token,
            state = transition.current,
            generation = generation,
            networkChanged = true
        )
    }

    private fun currentUnderlyingNetworkGeneration(): Long = synchronized(dnsStateLock) {
        underlyingNetworkGeneration
    }

    private fun scheduleNetworkStatusUpdate(
        token: Long,
        state: UnderlyingNetworkSnapshot,
        generation: Long,
        networkChanged: Boolean
    ) {
        synchronized(networkCallbackLock) {
            if (token != networkCallbackToken || networkCallbackRegistration?.token != token) return
            networkStatusDebounceJob?.cancel()
            networkStatusDebounceJob = serviceScope.launch {
                delay(NETWORK_CHANGE_DEBOUNCE_MS)
                if (token != networkCallbackToken || !isVpnRunning) return@launch
                if (generation != currentUnderlyingNetworkGeneration()) return@launch
                val currentState = underlyingNetworkReducer.snapshot()
                if (currentState != state) return@launch
                if (networkChanged) {
                    resetOkHttpClientForUnderlyingNetworkChange()
                    val released = synchronized(dnsStateLock) {
                        if (
                            generation != underlyingNetworkGeneration ||
                            underlyingNetworkReducer.snapshot() != currentState
                        ) {
                            false
                        } else {
                            underlyingNetworkChangePending = false
                            true
                        }
                    }
                    if (!released) return@launch
                }

                val recoveryMeasurement = if (
                    currentState.connectivity == UnderlyingNetworkConnectivity.ONLINE
                ) completeNetworkRecoveryMeasurement() else null
                addLog(networkStatusMessage(currentState, generation, networkChanged, recoveryMeasurement))
                if (lifecycleStateFlow.value == VpnLifecycleState.RUNNING) {
                    runCatching {
                        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                        manager.notify(NOTIFICATION_ID, createNotification(notificationText(VpnLifecycleState.RUNNING)))
                    }.onFailure { exception ->
                        Log.w(TAG, "Unable to refresh notification after network change", exception)
                    }
                }
            }
        }
    }

    private fun networkStatusMessage(
        state: UnderlyingNetworkSnapshot,
        generation: Long,
        networkChanged: Boolean,
        recoveryMeasurement: NetworkRecoveryMeasurement?
    ): String {
        val primary = synchronized(dnsStateLock) { upstreamDnsServer.primaryIp }
        val recovery = if (networkChanged) {
            "網路已切換，DNS 快取已清除、舊網路查詢已取消並重設 DoH 退避。"
        } else {
            ""
        }
        val retainedResolver = "目前選用的 DNS $primary 維持不變。"
        return when (state.connectivity) {
            UnderlyingNetworkConnectivity.OFFLINE ->
                "[網路狀態] 目前沒有可用網路，DNS 查詢會暫時失敗。$recovery$retainedResolver"
            UnderlyingNetworkConnectivity.CONNECTING ->
                "[網路狀態] 網路正在連線或檢查可用性。$recovery$retainedResolver"
            UnderlyingNetworkConnectivity.CAPTIVE_PORTAL ->
                "[網路狀態] 偵測到需要登入的網路入口，請先完成 Wi-Fi 或網路登入。$recovery$retainedResolver"
            UnderlyingNetworkConnectivity.ONLINE ->
                if (recoveryMeasurement != null) {
                    val measurement = recoveryMeasurement.let { result ->
                        val duration = result.durationMillis?.let { "恢復耗時 ${it} ms，" } ?: ""
                        "${duration}恢復期間失敗的 DNS 查詢有 ${result.failedQueryCount} 筆。"
                    }
                    "[網路恢復] 非 VPN 網路已就緒（generation $generation）。$measurement$recovery$retainedResolver"
                } else {
                    "[網路狀態] 網路連線正常。$retainedResolver"
                }
        }
    }

    private fun unregisterUnderlyingNetworkCallback() {
        val registration = synchronized(networkCallbackLock) {
            networkCallbackToken++
            networkStatusDebounceJob?.cancel()
            networkStatusDebounceJob = null
            networkCallbackRegistration.also { networkCallbackRegistration = null }
        }
        synchronized(underlyingNetworkEventLock) {
            underlyingNetworkReducer.clear()
            networkRecoveryTracker.clear()
        }
        synchronized(dnsStateLock) {
            underlyingNetworkChangePending = false
        }
        registration?.let {
            it.callbacks.forEach { callback ->
                try {
                    it.manager.unregisterNetworkCallback(callback)
                } catch (exception: Exception) {
                    Log.w(TAG, "Unable to unregister an underlying network callback", exception)
                }
            }
        }
    }

    private fun completeNetworkRecoveryMeasurement(): NetworkRecoveryMeasurement? =
        networkRecoveryTracker.takeCompletedMeasurement()

    private fun recordNetworkRecoveryFailure() {
        networkRecoveryTracker.recordFailure()
    }

    private suspend fun awaitStableUnderlyingNetwork(
        dnsState: DnsStateSnapshot,
        deadline: DnsRequestDeadline
    ): Boolean {
        while (true) {
            if (!isCurrentDnsState(dnsState)) return false
            val changePending = synchronized(dnsStateLock) { underlyingNetworkChangePending }
            if (!changePending) return true

            val remainingMillis = deadline.remainingMillis()
            if (remainingMillis <= 0L) return false
            delay(minOf(remainingMillis, NETWORK_CHANGE_POLL_MS))
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        serviceScope.launch(Dispatchers.Main.immediate) {
            for (command in lifecycleCommands) {
                when (command) {
                    is LifecycleCommand.Start -> {
                        startVpn(command.requestGeneration)
                        if (lifecycleStateFlow.value == VpnLifecycleState.FAILED) {
                            stopSelfIfIdle(command.startId)
                        }
                    }
                    is LifecycleCommand.Stop -> {
                        stopVpn()
                        // A later START or RESTART may already be queued under a newer startId.
                        stopSelfResult(command.startId)
                    }
                    is LifecycleCommand.Restart -> {
                        restartTunnel(command.requestGeneration)
                        if (lifecycleStateFlow.value == VpnLifecycleState.FAILED) {
                            stopSelfIfIdle(command.startId)
                        }
                    }
                    is LifecycleCommand.UpdateDns -> {
                        val server = withContext(Dispatchers.IO) {
                            AppDatabase.getDatabase(this@DnsVpnService)
                                .dnsDao()
                                .getDnsServerById(command.resolverId)
                        }
                        if (server != null) {
                            updateResolverState(server)
                            activeDnsFlow.value = "${server.name} (${server.primaryIp})"
                            addLog("[DNS 變更同步] 已即時套用新 DNS 設定：${server.name} (${server.primaryIp})")
                        } else {
                            addLog("[DNS 變更同步] 找不到 DNS 設定 id=${command.resolverId}")
                        }
                        stopSelfIfIdle(command.startId)
                    }
                    is LifecycleCommand.ClearLogs -> {
                        clearLogs()
                        stopSelfIfIdle(command.startId)
                    }
                    is LifecycleCommand.TunnelEnded -> handleTunnelEnded(command)
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestLifecycleStartId = startId
        when (intent?.action) {
            ACTION_START -> {
                userIntentStore.markExplicitStart()
                addLog("Starting service command received")
                val requestGeneration = lifecycleRequests.nextRequest()
                lifecycleCommands.trySend(LifecycleCommand.Start(startId, requestGeneration))
            }
            ACTION_STOP -> {
                userIntentStore.markExplicitStop()
                stopService(Intent(this, VpnRecoveryService::class.java))
                addLog("Stopping service command received")
                lifecycleRequests.nextRequest()
                lifecycleCommands.trySend(LifecycleCommand.Stop(startId))
            }
            ACTION_RESTART -> {
                addLog("Restarting service command received")
                val requestGeneration = lifecycleRequests.nextRequest()
                lifecycleCommands.trySend(LifecycleCommand.Restart(startId, requestGeneration))
            }
            ACTION_UPDATE_DNS -> {
                val resolverId = intent.getIntExtra("resolverId", -1)
                if (resolverId >= 0) {
                    lifecycleCommands.trySend(LifecycleCommand.UpdateDns(startId, resolverId))
                }
            }
            ACTION_CLEAR_LOGS -> {
                lifecycleCommands.trySend(LifecycleCommand.ClearLogs(startId))
            }
            ACTION_RELOAD_DOMAIN_POLICY -> {
                serviceScope.launch { reloadDomainPolicy() }
            }
            null, VpnService.SERVICE_INTERFACE -> {
                val userIntent = userIntentStore.snapshot()
                if (userIntent.shouldRecoverFromSystemStart(systemAlwaysOnEnabled())) {
                    addLog("System recovery command received; restoring the requested VPN state")
                    val requestGeneration = lifecycleRequests.nextRequest()
                    lifecycleCommands.trySend(LifecycleCommand.Start(startId, requestGeneration))
                } else {
                    if (lifecycleStateFlow.value == VpnLifecycleState.STOPPED ||
                        lifecycleStateFlow.value == VpnLifecycleState.FAILED) {
                        enterForeground(createNotification(notificationText(VpnLifecycleState.STOPPED)))
                    }
                    stopSelfIfIdle(startId)
                }
            }
        }
        return if (userIntentStore.snapshot().shouldUseStickyServiceStart(systemAlwaysOnEnabled())) {
            START_STICKY
        } else {
            START_NOT_STICKY
        }
    }

    override fun onDestroy() {
        lifecycleRequests.nextRequest()
        lifecycleCommands.close()
        closeTunnelResources()
        serviceJob.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        addLog("VPN connection revoked by system settings")
        userIntentStore.markAuthorizationRevoke()
        stopService(Intent(this, VpnRecoveryService::class.java))
        lifecycleRequests.nextRequest()
        lifecycleCommands.trySend(LifecycleCommand.Stop(latestLifecycleStartId))
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

    private suspend fun startVpn(requestGeneration: Long) {
        if (!lifecycleRequests.isCurrent(requestGeneration) || !lifecycleStateFlow.value.canStart) return

        updateLifecycleState(VpnLifecycleState.STARTING)
        var establishedFd: ParcelFileDescriptor? = null
        try {
            val notification = createNotification(notificationText(VpnLifecycleState.STARTING))
            enterForeground(notification)
            // The VPN is already foreground; the keeper promotes itself only while authorized.
            startService(Intent(this, VpnRecoveryService::class.java))

            reloadDomainPolicy(requestGeneration)
            if (!lifecycleRequests.isCurrent(requestGeneration)) {
                abandonSupersededStartup()
                return
            }
            val (activeServer, bypassedList) = withContext(Dispatchers.IO) {
                val database = AppDatabase.getDatabase(this@DnsVpnService)
                database.dnsDao().getActiveDnsServer() to database.dnsDao().getBypassedAppsList()
            }
            if (!lifecycleRequests.isCurrent(requestGeneration)) {
                abandonSupersededStartup()
                return
            }
            val resolver = activeServer ?: DnsServer(
                name = "Google DNS",
                primaryIp = "8.8.8.8",
                secondaryIp = "8.8.4.4"
            )
            updateResolverState(resolver)
            dnsTransportStatusFlow.value = "尚無上游查詢"
            activeDnsFlow.value = "${resolver.name} (${resolver.primaryIp})"
            addLog("Database loaded. Upstream DNS: ${resolver.name} (${resolver.primaryIp})")
            addLog("Loaded " + bypassedList.size + " apps to exempt/bypass DNS VPN")

            // Keep establish() on the service dispatcher so destruction cannot race descriptor ownership.
            val builder = Builder()
                .setSession("DNS Shield")
                .setBlocking(true)
                .setMtu(DnsResponsePacketBuilder.TUN_MTU_BYTES)
                .addAddress(VPN_IP, 32)
                .addRoute(DUMMY_DNS_IP, 32)
                .addDnsServer(DUMMY_DNS_IP)

            for (app in bypassedList) {
                try {
                    builder.addDisallowedApplication(app.packageName)
                    addLog("Exempted app: " + app.appName + " (" + app.packageName + ")")
                } catch (exception: PackageManager.NameNotFoundException) {
                    Log.w(TAG, "Exempted app package not found on device: " + app.packageName)
                } catch (exception: Exception) {
                    Log.e(TAG, "Error adding disallowed package: " + app.packageName, exception)
                }
            }

            yield()
            if (!lifecycleRequests.isCurrent(requestGeneration)) {
                abandonSupersededStartup()
                return
            }
            val descriptor = establishVpnTunnel(
                establish = { builder.establish() },
                onUnavailable = {
                    if (!lifecycleRequests.isCurrent(requestGeneration)) {
                        abandonSupersededStartup()
                    } else {
                        addLog("Error: Failed to establish VPN interface (null)")
                        updateLifecycleState(VpnLifecycleState.FAILED)
                        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
                    }
                }
            ) ?: return

            establishedFd = descriptor
            // Include rules saved while the VPN interface was being established.
            reloadDomainPolicy(requestGeneration)
            if (!lifecycleRequests.isCurrent(requestGeneration)) {
                runCatching { descriptor.close() }
                establishedFd = null
                abandonSupersededStartup()
                return
            }
            val generation = ++tunnelGeneration
            val activeJob = SupervisorJob(serviceJob)
            val activeTunnelScope = CoroutineScope(activeJob + Dispatchers.IO)
            vpnInterface = descriptor
            tunnelParentJob = activeJob
            tunnelScope = activeTunnelScope
            updateLifecycleState(VpnLifecycleState.RUNNING)
            registerUnderlyingNetworkCallback()
            addLog("[防護成功] 安全 DNS 防護已成功啟動並建立通道。")

            val activeNotification = createNotification(notificationText(VpnLifecycleState.RUNNING))
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIFICATION_ID, activeNotification)
            addLog("VPN Interface Established. Reading packets...")
            activeTunnelScope.launch { runTunnel(descriptor, generation) }
            establishedFd = null
        } catch (exception: CancellationException) {
            unregisterUnderlyingNetworkCallback()
            establishedFd?.let { descriptor ->
                if (vpnInterface === descriptor) {
                    tunnelGeneration++
                    vpnInterface = null
                    tunnelParentJob?.cancel()
                    tunnelParentJob = null
                    tunnelScope = null
                }
                runCatching { descriptor.close() }
            }
            updateLifecycleState(VpnLifecycleState.STOPPED)
            throw exception
        } catch (exception: Exception) {
            unregisterUnderlyingNetworkCallback()
            establishedFd?.let { descriptor ->
                if (vpnInterface === descriptor) {
                    tunnelGeneration++
                    vpnInterface = null
                    tunnelParentJob?.cancel()
                    tunnelParentJob = null
                    tunnelScope = null
                }
                runCatching { descriptor.close() }
            }
            if (!lifecycleRequests.isCurrent(requestGeneration)) {
                abandonSupersededStartup()
                return
            }
            addLog("VPN failed to start: " + exception.message)
            updateLifecycleState(VpnLifecycleState.FAILED)
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        }
    }

    private fun abandonSupersededStartup() {
        unregisterUnderlyingNetworkCallback()
        updateLifecycleState(VpnLifecycleState.STOPPED)
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
    }

    private fun runTunnel(descriptor: ParcelFileDescriptor, generation: Long) {
        var tcp: NativeDnsTcpRuntime? = null
        runVpnTunnelReader(
            openInput = { FileInputStream(descriptor.fileDescriptor) },
            openOutput = { FileOutputStream(descriptor.fileDescriptor) },
            isActive = { isVpnRunning && generation == tunnelGeneration },
            onOutputOpened = { outputStream ->
                synchronized(tcpRuntimeLock) {
                    if (isVpnRunning && generation == tunnelGeneration) {
                        NativeDnsTcpRuntime(
                            handler = { payload, send -> kotlinx.coroutines.runBlocking { handleTcpQuery(payload, send) } },
                            sendPacket = { packet -> synchronized(outputStream) { outputStream.write(packet) } },
                            onFailure = { runCatching { descriptor.close() } }
                        ).also { active ->
                            tcpRuntime = active
                            active.start()
                            tcp = active
                        }
                    }
                }
            },
            handlePacket = { buffer, readBytes, outputStream ->
                if (tcp?.offer(buffer, readBytes) != true) handlePacket(buffer, readBytes, outputStream)
            },
            onOutputClosing = {
                val active = synchronized(tcpRuntimeLock) { tcpRuntime.also { tcpRuntime = null } }
                active?.close()
                tcp = null
            },
            onEnded = { failure ->
                lifecycleCommands.trySend(
                    LifecycleCommand.TunnelEnded(generation, descriptor, failure)
                )
            }
        )
    }
    private fun handlePacket(packet: ByteArray, length: Int, outputStream: FileOutputStream) {
        val receivedAtNanos = System.nanoTime()
        when (val parsed = DnsIpv4UdpQueryParser.parse(packet, length)) {
            is Ipv4UdpDnsParseResult.Query -> {
                val dnsPacket = parsed.packet
                handleDnsQuery(dnsPacket, receivedAtNanos, DnsResponseWriter { response ->
                    sendResponsePacket(response, dnsPacket.sourceIp, dnsPacket.destinationIp,
                        dnsPacket.sourcePort, outputStream, query = dnsPacket.query)
                })
            }
            Ipv4UdpDnsParseResult.NotDns -> return
            is Ipv4UdpDnsParseResult.Rejected -> {
                val request = beginDnsRequest(receivedAtNanos)
                try {
                    parsed.dnsErrorResponse?.let { response ->
                        sendResponsePacket(
                            responseData = response.dnsPayload,
                            clientIp = response.clientIp,
                            mockDnsIp = response.resolverIp,
                            clientPort = response.clientPort,
                            outputStream = outputStream
                        )
                    }
                } finally {
                    completeDnsRequest(request, DnsClientTerminalOutcome.REJECTED)
                }
            }
        }
    }

    private suspend fun handleTcpQuery(payload: ByteArray, send: (ByteArray) -> Unit) {
        val receivedAtNanos = System.nanoTime()
        val parsed = DnsMessageValidator.parseQuery(payload)
        if (parsed is DnsQueryParseResult.Rejected) {
            val request = beginDnsRequest(receivedAtNanos)
            try {
                DnsMessageValidator.buildParseErrorResponse(payload, parsed.reason)?.let(send)
            } finally {
                completeDnsRequest(request, DnsClientTerminalOutcome.REJECTED)
            }
            return
        }
        val query = (parsed as DnsQueryParseResult.Valid).query
        val result = kotlinx.coroutines.CompletableDeferred<ByteArray>()
        val packet = ParsedIpv4UdpDnsQuery(byteArrayOf(10, 0, 0, 2),
            byteArrayOf(10, 0, 0, 1), 53, payload, query)
        handleDnsQuery(packet, receivedAtNanos, DnsResponseWriter {
            // Commit one immutable response while the resolver-state lock is held.
            // Stream I/O happens below so a slow TCP peer cannot hold that lock.
            result.complete(it.copyOf())
        })
        val response = withTimeout(6_100L) { result.await() }
        send(response)
    }

    private fun handleDnsQuery(
        dnsPacket: ParsedIpv4UdpDnsQuery,
        receivedAtNanos: Long,
        responseWriter: DnsResponseWriter
    ) {
        val request = beginDnsRequest(receivedAtNanos)
        val dnsState = snapshotDnsState()
        val queryKey = DnsQueryKey(
            bytes = dnsPacket.payload,
            resolverGeneration = dnsState.resolverGeneration,
            underlyingNetworkGeneration = dnsState.underlyingNetworkGeneration,
            policyAssembly = dnsState.policyAssembly
        )
        if (tryHandleFastPath(dnsPacket, dnsState, queryKey, request, responseWriter)) return

        val activeScope = tunnelScope
        if (activeScope == null || !activeScope.isActive) {
            sendServFailResponse(dnsPacket, responseWriter)
            completeDnsRequest(request, DnsClientTerminalOutcome.FAILED)
            return
        }

        val lease = when (val admission = queryAdmission.tryAdmit(queryKey)) {
            is DnsQueryAdmission.Leader -> admission.lease
            is DnsQueryAdmission.Waiter -> {
                recordCoalesced(request)
                admission.lease
            }
            DnsQueryAdmission.Rejected -> {
                recordOverload(request)
                sendServFailResponse(dnsPacket, responseWriter)
                completeDnsRequest(request, DnsClientTerminalOutcome.FAILED)
                if (isUiForeground || backgroundFailureLogLimiter.tryAcquire()) {
                    addDnsQueryLog(important = true) {
                        "✗ 有界請求容量已滿 [ID=${formatTxId(dnsPacket.payload)}]，已立即回覆 SERVFAIL"
                    }
                }
                return
            }
        }
        val deadline = DnsRequestDeadline.fromReceivedAt(receivedAtNanos)
        val networkCancellationResponseSent = AtomicBoolean(false)
        val requestJob = activeScope.launch(start = CoroutineStart.LAZY) {
            try {
                val outcome = forwardAdmittedDnsQuery(
                    dnsPacket = dnsPacket,
                    dnsState = dnsState,
                    queryKey = queryKey,
                    deadline = deadline,
                    lease = lease,
                    request = request,
                    responseWriter = responseWriter
                )
                completeDnsRequest(request, outcome)
            } catch (exception: CancellationException) {
                completeDnsRequest(request, DnsClientTerminalOutcome.FAILED)
                if (isVpnRunning && activeScope.isActive && !isCurrentDnsState(dnsState)) {
                    if (lease.isLeader) queryAdmission.completeLeader(lease, null)
                    if (networkCancellationResponseSent.compareAndSet(false, true)) {
                        sendServFailResponse(dnsPacket, responseWriter)
                    }
                } else {
                    throw exception
                }
            } catch (exception: Exception) {
                Log.e(TAG, "Failed in DNS query coroutine", exception)
                if (lease.isLeader) queryAdmission.completeLeader(lease, null)
                sendServFailResponse(dnsPacket, responseWriter)
                completeDnsRequest(request, DnsClientTerminalOutcome.FAILED)
            }
        }
        if (lease.isLeader) activeDnsLeaders[requestJob] = dnsState
        requestJob.invokeOnCompletion { completion ->
            completeDnsRequest(request, DnsClientTerminalOutcome.FAILED)
            activeDnsLeaders.remove(requestJob)
            if (lease.isLeader) queryAdmission.completeLeader(lease, null)
            queryAdmission.release(lease)
            if (
                completion is CancellationException &&
                lease.isLeader &&
                isVpnRunning &&
                activeScope.isActive &&
                !isCurrentDnsState(dnsState) &&
                networkCancellationResponseSent.compareAndSet(false, true)
            ) {
                sendServFailResponse(dnsPacket, responseWriter)
            }
        }
        requestJob.start()
    }
    private fun tryHandleFastPath(
        dnsPacket: ParsedIpv4UdpDnsQuery,
        dnsState: DnsStateSnapshot,
        queryKey: DnsQueryKey,
        request: DnsDiagnosticMetrics.Request,
        responseWriter: DnsResponseWriter
    ): Boolean {
        val cachedResponse = try {
            getCache(queryKey)
        } catch (exception: Exception) {
            Log.e(TAG, "Failed to read DNS cache", exception)
            sendServFailResponse(dnsPacket, responseWriter)
            completeDnsRequest(request, DnsClientTerminalOutcome.FAILED)
            return true
        }
        if (cachedResponse != null) {
            if (!sendResolvedResponseIfCurrent(dnsPacket, dnsState, cachedResponse, responseWriter)) {
                sendServFailResponse(dnsPacket, responseWriter)
                completeDnsRequest(request, DnsClientTerminalOutcome.FAILED)
                return true
            }
            recordCacheHit(request)
            completeDnsRequest(request, DnsClientTerminalOutcome.RESOLVED)
            val domain = dnsPacket.query.question.domainName ?: "Unknown"
            addDnsQueryLog {
                "⚡ [快取解析] [ID=${formatTxId(dnsPacket.payload)}]: $domain (記憶體命中, ${cachedResponse.size} bytes)"
            }
            return true
        }

        val domain = dnsPacket.query.question.domainName ?: "Unknown"
        val isBlocked = try {
            isAdOrTracker(domain, dnsState.policyAssembly)
        } catch (exception: Exception) {
            Log.e(TAG, "Failed to evaluate DNS block policy", exception)
            sendServFailResponse(dnsPacket, responseWriter)
            completeDnsRequest(request, DnsClientTerminalOutcome.FAILED)
            return true
        }
        if (!isBlocked) {
            if (!isCurrentDnsState(dnsState)) {
                sendServFailResponse(dnsPacket, responseWriter)
                completeDnsRequest(request, DnsClientTerminalOutcome.FAILED)
                return true
            }
            return false
        }

        val blockedResponse = DnsMessageValidator.buildNxDomainResponse(dnsPacket.query)
        if (!sendResolvedResponseIfCurrent(dnsPacket, dnsState, blockedResponse, responseWriter)) {
            sendServFailResponse(dnsPacket, responseWriter)
            completeDnsRequest(request, DnsClientTerminalOutcome.FAILED)
            return true
        }
        val savedBytes = estimateSavedBytes(domain)
        completeDnsRequest(request, DnsClientTerminalOutcome.BLOCKED, savedBytes = savedBytes)
        val reason = if (
            dnsState.policyAssembly.userRuleMatcher.decisionFor(domain) == DomainRuleAction.BLOCK
        ) DnsDecisionReason.USER_RULE else DnsDecisionReason.PROTECTION_LIST
        recordBlockedDomain(domain, reason)
        addDnsQueryLog { "🛡️ [真正攔截] $domain -> NXDOMAIN" }
        return true
    }

    private fun sendResolvedResponseIfCurrent(
        dnsPacket: ParsedIpv4UdpDnsQuery,
        dnsState: DnsStateSnapshot,
        response: ByteArray,
        responseWriter: DnsResponseWriter
    ): Boolean = DnsResolvedResponseCommitter.sendIfCurrent(
        stateLock = dnsStateLock,
        isCurrent = { isCurrentDnsState(dnsState) },
        response = response,
        transactionIdSource = dnsPacket.payload,
        responseWriter = responseWriter
    )

    private fun sendServFailResponse(
        dnsPacket: ParsedIpv4UdpDnsQuery,
        responseWriter: DnsResponseWriter
    ) {
        recordNetworkRecoveryFailure()
        responseWriter.send(DnsMessageValidator.buildServFailResponse(dnsPacket.query))
    }

    private fun putCacheIfCurrentState(
        dnsState: DnsStateSnapshot,
        queryKey: DnsQueryKey,
        response: ByteArray,
        query: ParsedDnsQuery
    ): Boolean = synchronized(dnsStateLock) {
        if (!isCurrentDnsStateLocked(dnsState)) {
            false
        } else {
            putCache(queryKey, response, query)
            true
        }
    }

    private suspend fun performDohLookup(
        endpoint: DnsDohEndpoint,
        resolverEndpoints: List<DnsDohEndpoint>,
        query: ParsedDnsQuery,
        deadline: DnsRequestDeadline,
        metricsRequest: DnsDiagnosticMetrics.Request
    ): ByteArray? {
        if (deadline.remainingMillis() <= 0L) return null
        return getOkHttpClient()
            .forDohEndpoints(resolverEndpoints)
            .lookupDoh(
                endpointUrl = endpoint.url,
                query = query,
                deadline = deadline,
                onCallQueued = { recordTransportAttempt(metricsRequest, DnsUpstreamTransport.DOH_CALL_QUEUED) },
                logFailure = { message, error -> logDnsTransportFailure(message, error) }
            )
    }

    private fun sendResponsePacket(
        responseData: ByteArray,
        clientIp: ByteArray,
        mockDnsIp: ByteArray,
        clientPort: Int,
        outputStream: FileOutputStream,
        transactionIdSource: ByteArray? = null,
        query: ParsedDnsQuery? = null
    ) {
        val responseForClient = transactionIdSource?.let { copyResponseWithTxId(responseData, it) }
            ?: responseData
        val clientResponse = query?.let { dnsQuery ->
            DnsMessageValidator.truncateResponseForClient(
                responseForClient,
                dnsQuery,
                DnsMessageValidator.maxClientUdpResponseBytes(dnsQuery)
            ) ?: DnsMessageValidator.buildServFailResponse(dnsQuery)
        } ?: responseData
        val responseIpPacket = DnsResponsePacketBuilder.build(
            srcIp = mockDnsIp, // 10.0.0.1
            dstIp = clientIp,   // Client IP
            srcPort = 53,
            dstPort = clientPort,
            payload = clientResponse,
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

    private suspend fun forwardAdmittedDnsQuery(
        dnsPacket: ParsedIpv4UdpDnsQuery,
        dnsState: DnsStateSnapshot,
        queryKey: DnsQueryKey,
        deadline: DnsRequestDeadline,
        lease: BoundedDnsQueryAdmission.Lease<DnsQueryKey>,
        request: DnsDiagnosticMetrics.Request,
        responseWriter: DnsResponseWriter
    ): DnsClientTerminalOutcome {
        val dnsPayload = dnsPacket.payload
        val query = dnsPacket.query
        val domain = query.question.domainName ?: "Unknown"
        if (!isCurrentDnsState(dnsState)) {
            if (lease.isLeader) queryAdmission.completeLeader(lease, null)
            sendServFailResponse(dnsPacket, responseWriter)
            return DnsClientTerminalOutcome.FAILED
        }
        if (lease.isLeader && !awaitStableUnderlyingNetwork(dnsState, deadline)) {
            queryAdmission.completeLeader(lease, null)
            sendServFailResponse(dnsPacket, responseWriter)
            return DnsClientTerminalOutcome.FAILED
        }
        val sharedResponse = if (lease.isLeader) {
            try {
                val remainingMillis = deadline.remainingMillis()
                if (remainingMillis <= 0L) {
                    null
                } else {
                    withTimeoutOrNull(remainingMillis) {
                        val response = resolveUpstreamQuery(dnsPayload, query, domain, dnsState, deadline, request)
                        val validatedResponse = response?.takeIf {
                            DnsMessageValidator.isValidResponse(it, query)
                        }
                        if (validatedResponse != null &&
                            !putCacheIfCurrentState(dnsState, queryKey, validatedResponse, query)
                        ) {
                            return@withTimeoutOrNull null
                        }
                        validatedResponse?.takeIf {
                            deadline.remainingMillis() > 0L && isCurrentDnsState(dnsState)
                        }
                    }
                }
            } catch (exception: CancellationException) {
                throw exception
            } catch (exception: Exception) {
                Log.e(TAG, "DNS resolution leader failed", exception)
                null
            }.also { queryAdmission.completeLeader(lease, it) }
        } else {
            val remainingMillis = deadline.remainingMillis()
            if (remainingMillis <= 0L) null else withTimeoutOrNull(remainingMillis) { lease.result.await() }
        }

        if (sharedResponse != null) {
            if (!sendResolvedResponseIfCurrent(dnsPacket, dnsState, sharedResponse, responseWriter)) {
                sendServFailResponse(dnsPacket, responseWriter)
                return DnsClientTerminalOutcome.FAILED
            }
            addDnsQueryLog {
                "✓ 解析成功 [ID=${formatTxId(dnsPayload)}]: $domain (${sharedResponse.size} bytes)"
            }
            return DnsClientTerminalOutcome.RESOLVED
        } else {
            sendServFailResponse(dnsPacket, responseWriter)
            if (isUiForeground || backgroundFailureLogLimiter.tryAcquire()) {
                addDnsQueryLog(important = true) {
                    "✗ 請求失敗 [ID=${formatTxId(dnsPayload)}]: $domain 伺服器逾時、超載或無回應"
                }
            }
            return DnsClientTerminalOutcome.FAILED
        }
    }

    private fun upstreamEndpoint(address: String) = DnsUdpUpstreamEndpoint(
        InetAddress.getByName(address),
        BuildConfig.DNS_UPSTREAM_PORT
    )

    private suspend fun resolveUpstreamQuery(
        dnsPayload: ByteArray,
        query: ParsedDnsQuery,
        domain: String,
        dnsState: DnsStateSnapshot,
        deadline: DnsRequestDeadline,
        request: DnsDiagnosticMetrics.Request
    ): ByteArray? {
        val endpoints = DohEndpointConfiguration.endpoints(dnsState.server)
        val outcome = DnsTransportPolicy.resolve(
            allowPlaintextFallback = dnsState.server.allowPlaintextFallback,
            endpoints = endpoints,
            deadline = deadline,
            dohQuery = { endpoint ->
                if (!isCurrentDnsState(dnsState) ||
                    !dohFailureBackoff.tryAcquire(endpoint.url, dnsState.underlyingNetworkGeneration)) {
                    null
                } else {
                    val response = try {
                        performDohLookup(endpoint, endpoints, query, deadline, request)
                    } catch (exception: CancellationException) {
                        dohFailureBackoff.cancelAttempt(endpoint.url, dnsState.underlyingNetworkGeneration)
                        throw exception
                    } catch (exception: Exception) {
                        dohFailureBackoff.recordFailure(endpoint.url, dnsState.underlyingNetworkGeneration)
                        logDnsTransportFailure("DoH resolution failed for ${endpoint.url}", exception)
                        null
                    }
                    if (response == null) {
                        dohFailureBackoff.recordFailure(endpoint.url, dnsState.underlyingNetworkGeneration)
                    } else {
                        dohFailureBackoff.recordSuccess(endpoint.url, dnsState.underlyingNetworkGeneration)
                    }
                    response
                }
            },
            plaintextQuery = {
                if (!dnsState.server.allowPlaintextFallback ||
                    !plaintextFallbackFence.allows(dnsState.server.id) ||
                    !isCurrentDnsState(dnsState) ||
                    deadline.remainingMillis() <= 0L
                ) {
                    null
                } else {
                    recordFallbackAttempt(request)
                    val socket = PolicyFencedDatagramSocket(
                        resolverId = dnsState.server.id,
                        snapshotAllowsPlaintext = dnsState.server.allowPlaintextFallback,
                        fence = plaintextFallbackFence,
                        currentPolicyAllowsPlaintext = {
                            isCurrentDnsState(dnsState) && deadline.remainingMillis() > 0L
                        }
                    )
                    try {
                        if (!protect(socket)) throw IOException("Failed to protect DNS UDP socket from the VPN.")
                        val upstreams = buildList {
                            add(upstreamEndpoint(dnsState.server.primaryIp))
                            dnsState.server.secondaryIp?.let { address ->
                                add(upstreamEndpoint(address))
                            }
                        }
                        DnsUdpUpstreamClient.queryWithFallback(
                            socket = socket,
                            query = query,
                            upstreams = upstreams,
                            deadline = deadline,
                            onAttempt = { recordTransportAttempt(request, DnsUpstreamTransport.UDP) },
                            onRetry = { recordUdpRetryAttempt(request) },
                            tcpQuery = { upstream ->
                                if (!dnsState.server.allowPlaintextFallback ||
                                    !plaintextFallbackFence.allows(dnsState.server.id) ||
                                    !isCurrentDnsState(dnsState) ||
                                    deadline.remainingMillis() <= 0L
                                ) {
                                    null
                                } else {
                                    val tcpSocket = Socket()
                                    try {
                                        DnsTcpUpstreamClient.query(
                                            socket = tcpSocket,
                                            query = query,
                                            server = upstream.address,
                                            port = upstream.port,
                                            deadline = deadline,
                                            prepareSocket = { candidate ->
                                                if (!plaintextFallbackFence.registerTcpSocketIfAllowed(
                                                        resolverId = dnsState.server.id,
                                                        snapshotAllowsPlaintext = dnsState.server.allowPlaintextFallback,
                                                        currentPolicyAllowsPlaintext = {
                                                            isCurrentDnsState(dnsState) && deadline.remainingMillis() > 0L
                                                        },
                                                        socket = candidate
                                                    )
                                                ) {
                                                    false
                                                } else if (!protect(candidate)) {
                                                    throw IOException("Failed to protect DNS TCP socket from the VPN.")
                                                } else {
                                                    true
                                                }
                                            },
                                            sendQueryFrame = { candidate, frame ->
                                                plaintextFallbackFence.writeTcpFrameIfAllowed(
                                                    resolverId = dnsState.server.id,
                                                    snapshotAllowsPlaintext = dnsState.server.allowPlaintextFallback,
                                                    currentPolicyAllowsPlaintext = {
                                                        isCurrentDnsState(dnsState) && deadline.remainingMillis() > 0L
                                                    },
                                                    socket = candidate,
                                                    frame = frame
                                                ).also { sent ->
                                                    if (sent) recordTransportAttempt(request, DnsUpstreamTransport.TCP)
                                                }
                                            }
                                        )
                                    } finally {
                                        try {
                                            tcpSocket.close()
                                        } finally {
                                            plaintextFallbackFence.unregisterTcpSocket(
                                                dnsState.server.id,
                                                tcpSocket
                                            )
                                        }
                                    }
                                }
                            }
                        )
                    } finally {
                        socket.close()
                    }
                }
            }
        )

        if (!isCurrentDnsState(dnsState)) return null
        when (outcome.transport) {
            DnsTransport.ENCRYPTED_HTTPS -> {
                dnsTransportStatusFlow.value = "DoH 加密"
                addDnsQueryLog {
                    "🌐 [DoH 解析] [ID=${formatTxId(dnsPayload)}]: 透過 HTTPS 解析 $domain"
                }
            }
            DnsTransport.PLAINTEXT_UDP -> {
                dnsTransportStatusFlow.value = "UDP/53 明文降級"
                addDnsQueryLog(important = true) {
                    "⚠️ [DNS 降級] [ID=${formatTxId(dnsPayload)}]: DoH 不可用，改用 UDP/53 解析 $domain"
                }
            }
            DnsTransport.PLAINTEXT_TCP -> {
                dnsTransportStatusFlow.value = "TCP/53 明文降級"
                addDnsQueryLog(important = true) {
                    "⚠️ [DNS 降級] [ID=${formatTxId(dnsPayload)}]: UDP 回應遭截短，改用 TCP/53 解析 $domain"
                }
            }
            DnsTransport.UNAVAILABLE -> {
                dnsTransportStatusFlow.value = if (dnsState.server.allowPlaintextFallback) {
                    "上游不可用 · SERVFAIL"
                } else {
                    "僅加密 · DoH 不可用 · SERVFAIL"
                }
            }
        }
        return outcome.response?.takeIf { deadline.remainingMillis() > 0L && isCurrentDnsState(dnsState) }
    }

    private fun formatTxId(dnsPayload: ByteArray): String {
        return if (dnsPayload.size >= 2) {
            String.format("0x%02X%02X", dnsPayload[0], dnsPayload[1])
        } else {
            "Unknown"
        }
    }

    private suspend fun handleTunnelEnded(command: LifecycleCommand.TunnelEnded) {
        if (!isCurrentTunnelEnded(
                endedGeneration = command.generation,
                currentGeneration = tunnelGeneration,
                endedDescriptor = command.descriptor,
                currentDescriptor = vpnInterface,
                lifecycleState = lifecycleStateFlow.value
            )
        ) return

        addLog(command.failure ?: "VPN tunnel stopped unexpectedly")
        stopVpn(finalState = VpnLifecycleState.FAILED)
    }

    private fun updateLifecycleState(state: VpnLifecycleState) {
        lifecycleStateFlow.value = state
        isVpnRunning = state.isRunning
    }

    private fun enterForeground(notification: Notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun stopSelfIfIdle(startId: Int) {
        if (
            lifecycleStateFlow.value == VpnLifecycleState.STOPPED ||
            lifecycleStateFlow.value == VpnLifecycleState.FAILED
        ) {
            stopService(Intent(this, VpnRecoveryService::class.java))
            stopSelfResult(startId)
        }
    }

    private fun notificationText(state: VpnLifecycleState): String = when (state) {
        VpnLifecycleState.STOPPED -> "DNS Shield 防護已關閉"
        VpnLifecycleState.STARTING -> "DNS Shield 正在啟動防護…"
        VpnLifecycleState.RUNNING -> when {
            networkCallbackRegistration == null -> "DNS Shield 防護中"
            else -> when (underlyingNetworkReducer.snapshot().connectivity) {
                UnderlyingNetworkConnectivity.OFFLINE -> "DNS Shield 防護中，目前離線"
                UnderlyingNetworkConnectivity.CONNECTING -> "DNS Shield 防護中，正在確認網路連線"
                UnderlyingNetworkConnectivity.CAPTIVE_PORTAL -> "DNS Shield 防護中，網路需要登入"
                UnderlyingNetworkConnectivity.ONLINE -> "DNS Shield 防護中"
            }
        }
        VpnLifecycleState.STOPPING -> "DNS Shield 正在停止防護…"
        VpnLifecycleState.FAILED -> "DNS Shield 防護異常"
    }

    // Service destruction cannot suspend, so it closes the owned descriptor and cancels its session directly.
    private fun closeTunnelResources() {
        unregisterUnderlyingNetworkCallback()
        rulePolicyStatusFlow.value = RulePolicyStatus.NotLoaded
        val finalState = lifecycleStateFlow.value.stateAfterServiceDestroy()
        tunnelGeneration++
        if (finalState != VpnLifecycleState.FAILED) {
            updateLifecycleState(VpnLifecycleState.STOPPING)
        }
        synchronized(tcpRuntimeLock) { tcpRuntime?.requestStop() }
        val descriptor = vpnInterface
        val sessionJob = tunnelParentJob
        vpnInterface = null
        tunnelParentJob = null
        tunnelScope = null

        try {
            descriptor?.close()
        } catch (exception: Exception) {
            Log.e(TAG, "Error closing vpnInterface descriptor", exception)
        }
        sessionJob?.cancel()
        updateLifecycleState(finalState)
    }

    private suspend fun restartTunnel(requestGeneration: Long) {
        addLog("[安全防護] 正在重新啟動 DNS 隧道以套用新名單…")
        stopVpn()
        startVpn(requestGeneration)
    }

    private suspend fun stopVpn(finalState: VpnLifecycleState = VpnLifecycleState.STOPPED) {
        stopService(Intent(this, VpnRecoveryService::class.java))
        unregisterUnderlyingNetworkCallback()
        rulePolicyStatusFlow.value = RulePolicyStatus.NotLoaded
        addLog("正在關閉安全 DNS 防護隧道並釋放資源…")
        if (lifecycleStateFlow.value != VpnLifecycleState.STOPPED) {
            updateLifecycleState(VpnLifecycleState.STOPPING)
            val notification = createNotification(notificationText(VpnLifecycleState.STOPPING))
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIFICATION_ID, notification)
        }

        // Invalidate the ending callback before closing the descriptor or joining its job.
        tunnelGeneration++
        synchronized(tcpRuntimeLock) { tcpRuntime?.requestStop() }
        val descriptor = vpnInterface
        val sessionJob = tunnelParentJob
        vpnInterface = null
        tunnelParentJob = null
        tunnelScope = null

        closeVpnTunnelThenJoin(
            closeDescriptor = { descriptor?.close() },
            joinSession = { sessionJob?.cancelAndJoin() },
            onCloseFailure = { exception ->
                Log.e(TAG, "Error closing vpnInterface descriptor", exception)
            },
            onJoinFailure = { exception ->
                Log.e(TAG, "Exception cancelling tunnel session during shutdown", exception)
            }
        )

        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (exception: Exception) {
            Log.e(TAG, "Error stopping foreground service", exception)
        }

        updateLifecycleState(finalState)
        Log.i(TAG, "VPN stopped completely")
    }

    private fun createNotification(content: String): Notification = createVpnNotification(this, content)

    private fun createNotificationChannel() = createVpnNotificationChannel(this)

}
