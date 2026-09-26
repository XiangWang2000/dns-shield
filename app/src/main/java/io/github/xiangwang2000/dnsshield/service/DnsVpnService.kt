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
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.MainActivity
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyAssembly
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyCacheKey
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyDiagnostics
import io.github.xiangwang2000.dnsshield.blocking.ProductionBlocklistAssetLoader
import io.github.xiangwang2000.dnsshield.blocking.PublicSuffixResolverOwner
import io.github.xiangwang2000.dnsshield.blocking.PublicSuffixResolverStatus
import io.github.xiangwang2000.dnsshield.blocking.ReloadableDomainPolicy
import io.github.xiangwang2000.dnsshield.blocking.RuntimeDomainPolicy
import io.github.xiangwang2000.dnsshield.blocking.RuleBlocklistSource
import io.github.xiangwang2000.dnsshield.blocking.RulePolicyStatus
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.DnsServer
import kotlin.coroutines.resume
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
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
        private const val CHANNEL_ID = "dns_vpn_channel"
        private const val NOTIFICATION_ID = 5543
        private const val MAX_CONCURRENT_DNS_QUERIES = 24
        private const val MAX_COALESCED_DNS_QUERY_WAITERS = 8
        private const val MAX_LOG_LINES = 100
        private const val FOREGROUND_LOG_FLUSH_MS = 300L
        private const val FOREGROUND_STATS_FLUSH_MS = 500L
        private const val MEMORY_TRIM_CLEAR_CACHE_LEVEL = 60

        const val VPN_IP = "10.0.0.2"
        const val DUMMY_DNS_IP = "10.0.0.1"

        // Publish one lifecycle state for the UI and service notification.
        val lifecycleStateFlow = MutableStateFlow(VpnLifecycleState.STOPPED)
        val queryCountFlow = MutableStateFlow(0)
        val blockedAdsFlow = MutableStateFlow(0)
        val savedBytesFlow = MutableStateFlow(0L)
        val activeDnsFlow = MutableStateFlow("None")
        val dnsTransportStatusFlow = MutableStateFlow("尚無上游查詢")
        val liveLogsFlow = MutableStateFlow<List<String>>(emptyList())
        private val plaintextFallbackFence = DnsPlaintextFallbackFence()

        fun setPlaintextFallbackAllowed(resolverId: Int, allowed: Boolean) {
            plaintextFallbackFence.setAllowed(resolverId, allowed)
        }
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
                    .callTimeout(DnsRequestDeadline.DEFAULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
                    .connectionPool(ConnectionPool(5, 5, java.util.concurrent.TimeUnit.MINUTES))
                    .build().also { okHttpClientInstance = it }
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
    private val lifecycleCommands = Channel<LifecycleCommand>(Channel.UNLIMITED)
    private val lifecycleRequests = VpnLifecycleRequestTracker()
    private var latestLifecycleStartId = 0

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

    private data class DnsStateSnapshot(
        val server: DnsServer,
        val resolverGeneration: Int,
        val policyAssembly: DomainPolicyAssembly
    )

    private val dnsStateLock = Any()
    private var resolverGeneration = 0
    private val queryAdmission = BoundedDnsQueryAdmission<DnsQueryKey>(
        maxUniqueKeys = MAX_CONCURRENT_DNS_QUERIES,
        maxWaitersPerKey = MAX_COALESCED_DNS_QUERY_WAITERS
    )

    // Explicit, clean separation of VPN active running components from the general ServiceScope
    private var tunnelParentJob: Job? = null
    private var tunnelScope: CoroutineScope? = null
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

    private suspend fun reloadDomainPolicy(requestGeneration: Long) {
        try {
            val assembly = withContext(Dispatchers.IO) {
                RuntimeDomainPolicy.assemble(
                    filesDirectory = filesDir,
                    loadBundledBlocklist = productionBlocklistLoader::load,
                    bundledSourceMetadata = productionBlocklistLoader.sourceMetadata,
                    registrableDomainResolverProvider = {
                        publicSuffixResolverOwner.resolverOrNull()
                    }
                )
            }
            if (!lifecycleRequests.isCurrent(requestGeneration)) return
            domainPolicy.install(assembly) {
                invalidatePolicyState()
            }
            rulePolicyStatusFlow.value = assembly.displayStatus.copy(
                publicSuffixStatus = if (assembly.displayStatus.source == RuleBlocklistSource.BUILT_IN) {
                    PublicSuffixResolverStatus.NotLoaded
                } else {
                    publicSuffixResolverOwner.status()
                },
                reloadError = null
            )
        } catch (exception: CancellationException) {
            throw exception
        } catch (exception: Exception) {
            if (!lifecycleRequests.isCurrent(requestGeneration)) return
            val reason = exception.message?.takeIf(String::isNotBlank)
                ?: exception.javaClass.simpleName
            Log.e(TAG, "Failed to reload domain policy", exception)
            rulePolicyStatusFlow.value = rulePolicyStatusFlow.value.copy(reloadError = reason)
            addLog("[攔截規則] 重新載入失敗，保留目前規則：$reason")
            return
        }

        addLog(DomainPolicyDiagnostics.message(rulePolicyStatusFlow.value))
    }

    private fun clearDnsStateLocked() {
        synchronized(dnsCache) { dnsCache.evictAll() }
        blockDecisionCache.evictAll()
    }

    private fun snapshotDnsState(): DnsStateSnapshot = synchronized(dnsStateLock) {
        DnsStateSnapshot(
            server = upstreamDnsServer,
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
        serviceScope.launch(Dispatchers.Main.immediate) {
            for (command in lifecycleCommands) {
                when (command) {
                    is LifecycleCommand.Start -> {
                        startVpn(command.requestGeneration)
                        if (lifecycleStateFlow.value == VpnLifecycleState.FAILED) {
                            stopSelfResult(command.startId)
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
                            stopSelfResult(command.startId)
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
                addLog("Starting service command received")
                val requestGeneration = lifecycleRequests.nextRequest()
                lifecycleCommands.trySend(LifecycleCommand.Start(startId, requestGeneration))
            }
            ACTION_STOP -> {
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
        }
        return START_NOT_STICKY
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
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION_ID, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }

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
            val descriptor = builder.establish()
            if (descriptor == null) {
                if (!lifecycleRequests.isCurrent(requestGeneration)) {
                    abandonSupersededStartup()
                    return
                }
                addLog("Error: Failed to establish VPN interface (null)")
                updateLifecycleState(VpnLifecycleState.FAILED)
                runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
                return
            }

            establishedFd = descriptor
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
            addLog("[防護成功] 安全 DNS 防護已成功啟動並建立通道。")

            val activeNotification = createNotification(notificationText(VpnLifecycleState.RUNNING))
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIFICATION_ID, activeNotification)
            addLog("VPN Interface Established. Reading packets...")
            activeTunnelScope.launch { runTunnel(descriptor, generation) }
            establishedFd = null
        } catch (exception: CancellationException) {
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
        updateLifecycleState(VpnLifecycleState.STOPPED)
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
    }

    private fun runTunnel(descriptor: ParcelFileDescriptor, generation: Long) {
        var failure: String? = null
        var reportTunnelEnded = true
        try {
            val inputStream = FileInputStream(descriptor.fileDescriptor)
            try {
                val outputStream = FileOutputStream(descriptor.fileDescriptor)
                try {
                    val buffer = ByteArray(4096)
                    while (isVpnRunning && generation == tunnelGeneration) {
                        val readBytes = inputStream.read(buffer)
                        if (readBytes > 0) {
                            handlePacket(buffer, readBytes, outputStream)
                        } else if (readBytes < 0) {
                            failure = "Tunnel stream reached EOF unexpectedly"
                            break
                        }
                    }
                } finally {
                    outputStream.close()
                }
            } finally {
                inputStream.close()
            }
        } catch (exception: IOException) {
            if (isVpnRunning && generation == tunnelGeneration) {
                failure = "Tunnel read error: " + exception.message
            }
        } catch (exception: CancellationException) {
            reportTunnelEnded = false
            throw exception
        } catch (exception: Exception) {
            if (isVpnRunning && generation == tunnelGeneration) {
                failure = "Tunnel reader failed: " + (exception.message ?: exception.javaClass.simpleName)
            }
        } finally {
            if (reportTunnelEnded) {
                lifecycleCommands.trySend(
                    LifecycleCommand.TunnelEnded(generation, descriptor, failure)
                )
            }
        }
    }
    private fun handlePacket(packet: ByteArray, length: Int, outputStream: FileOutputStream) {
        val receivedAtNanos = System.nanoTime()
        when (val parsed = DnsIpv4UdpQueryParser.parse(packet, length)) {
            is Ipv4UdpDnsParseResult.Query -> {
                val dnsPacket = parsed.packet
                val dnsState = snapshotDnsState()
                val queryKey = DnsQueryKey(
                    bytes = dnsPacket.payload,
                    resolverGeneration = dnsState.resolverGeneration,
                    policyAssembly = dnsState.policyAssembly
                )
                if (tryHandleFastPath(dnsPacket, dnsState, queryKey, outputStream)) return

                val activeScope = tunnelScope
                if (activeScope == null || !activeScope.isActive) {
                    sendServFailResponse(dnsPacket, outputStream)
                    return
                }

                val lease = when (val admission = queryAdmission.tryAdmit(queryKey)) {
                    is DnsQueryAdmission.Leader -> admission.lease
                    is DnsQueryAdmission.Waiter -> admission.lease
                    DnsQueryAdmission.Rejected -> {
                        sendServFailResponse(dnsPacket, outputStream)
                        if (isUiForeground || backgroundFailureLogLimiter.tryAcquire()) {
                            addDnsQueryLog(important = true) {
                                "✗ 有界請求容量已滿 [ID=${formatTxId(dnsPacket.payload)}]，已立即回覆 SERVFAIL"
                            }
                        }
                        return
                    }
                }
                val deadline = DnsRequestDeadline.fromReceivedAt(receivedAtNanos)
                val requestJob = activeScope.launch {
                    try {
                        forwardAdmittedDnsQuery(
                            dnsPacket = dnsPacket,
                            dnsState = dnsState,
                            queryKey = queryKey,
                            deadline = deadline,
                            lease = lease,
                            outputStream = outputStream
                        )
                    } catch (exception: CancellationException) {
                        throw exception
                    } catch (exception: Exception) {
                        Log.e(TAG, "Failed in DNS query coroutine", exception)
                        if (lease.isLeader) queryAdmission.completeLeader(lease, null)
                        sendServFailResponse(dnsPacket, outputStream)
                    }
                }
                requestJob.invokeOnCompletion {
                    if (lease.isLeader) queryAdmission.completeLeader(lease, null)
                    queryAdmission.release(lease)
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

    private fun tryHandleFastPath(
        dnsPacket: ParsedIpv4UdpDnsQuery,
        dnsState: DnsStateSnapshot,
        queryKey: DnsQueryKey,
        outputStream: FileOutputStream
    ): Boolean {
        val cachedResponse = try {
            getCache(queryKey)
        } catch (exception: Exception) {
            Log.e(TAG, "Failed to read DNS cache", exception)
            sendServFailResponse(dnsPacket, outputStream)
            return true
        }
        if (cachedResponse != null) {
            if (!sendResolvedResponseIfCurrent(dnsPacket, dnsState, cachedResponse, outputStream)) {
                sendServFailResponse(dnsPacket, outputStream)
                return true
            }
            recordResolvedQuery()
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
            sendServFailResponse(dnsPacket, outputStream)
            return true
        }
        if (!isBlocked) return false

        val blockedResponse = DnsMessageValidator.buildNxDomainResponse(dnsPacket.query)
        sendResponsePacket(
            blockedResponse,
            dnsPacket.sourceIp,
            dnsPacket.destinationIp,
            dnsPacket.sourcePort,
            outputStream
        )
        recordBlockedQuery(estimateSavedBytes(domain))
        addDnsQueryLog { "🛡️ [真正攔截] $domain -> NXDOMAIN" }
        return true
    }

    private fun sendResolvedResponseIfCurrent(
        dnsPacket: ParsedIpv4UdpDnsQuery,
        dnsState: DnsStateSnapshot,
        response: ByteArray,
        outputStream: FileOutputStream
    ): Boolean = synchronized(dnsStateLock) {
        if (!isCurrentDnsState(dnsState)) {
            false
        } else {
            sendResponsePacket(
                responseData = response,
                clientIp = dnsPacket.sourceIp,
                mockDnsIp = dnsPacket.destinationIp,
                clientPort = dnsPacket.sourcePort,
                outputStream = outputStream,
                transactionIdSource = dnsPacket.payload
            )
            true
        }
    }

    private fun sendServFailResponse(
        dnsPacket: ParsedIpv4UdpDnsQuery,
        outputStream: FileOutputStream
    ) {
        sendResponsePacket(
            responseData = DnsMessageValidator.buildServFailResponse(dnsPacket.query),
            clientIp = dnsPacket.sourceIp,
            mockDnsIp = dnsPacket.destinationIp,
            clientPort = dnsPacket.sourcePort,
            outputStream = outputStream
        )
    }

    private suspend fun performDohLookup(
        endpoint: DnsDohEndpoint,
        resolverEndpoints: List<DnsDohEndpoint>,
        query: ParsedDnsQuery,
        deadline: DnsRequestDeadline
    ): ByteArray? {
        val remainingMillis = deadline.remainingMillis()
        if (remainingMillis <= 0L) return null

        val mediaType = "application/dns-message".toMediaType()
        val requestBody = DnsMessageValidator.prepareUpstreamQuery(query).toRequestBody(mediaType)

        val request = Request.Builder()
            .url(endpoint.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .post(requestBody)
            .build()

        val client = getOkHttpClient().forDohEndpoints(resolverEndpoints)
        val call = client.newCall(request)
        call.timeout().timeout(remainingMillis, TimeUnit.MILLISECONDS)

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
                        logDnsTransportFailure("DoH resolution failed for ${endpoint.url}", e)
                        continuation.resume(null)
                    }
                }

                override fun onResponse(call: okhttp3.Call, response: okhttp3.Response) {
                    try {
                        if (continuation.isActive) {
                            if (response.isSuccessful && response.request.url.isHttps) {
                                val body = response.body
                                val bytes = DnsDohResponseValidator.readValidatedBody(
                                    contentType = response.header("Content-Type"),
                                    contentLength = body.contentLength(),
                                    stream = body.byteStream(),
                                    query = query
                                )
                                continuation.resume(bytes)
                            } else {
                                logDnsTransportFailure("DoH resolution error: HTTP ${response.code} for ${endpoint.url}")
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

    private suspend fun forwardAdmittedDnsQuery(
        dnsPacket: ParsedIpv4UdpDnsQuery,
        dnsState: DnsStateSnapshot,
        queryKey: DnsQueryKey,
        deadline: DnsRequestDeadline,
        lease: BoundedDnsQueryAdmission.Lease<DnsQueryKey>,
        outputStream: FileOutputStream
    ) {
        val dnsPayload = dnsPacket.payload
        val query = dnsPacket.query
        val domain = query.question.domainName ?: "Unknown"
        val sharedResponse = if (lease.isLeader) {
            try {
                val remainingMillis = deadline.remainingMillis()
                if (remainingMillis <= 0L) {
                    null
                } else {
                    withTimeoutOrNull(remainingMillis) {
                        val response = resolveUpstreamQuery(dnsPayload, query, domain, dnsState, deadline)
                        val validatedResponse = response?.takeIf {
                            DnsMessageValidator.isValidResponse(it, query)
                        }
                        if (validatedResponse != null &&
                            isCurrentDnsState(dnsState)
                        ) {
                            putCache(queryKey, validatedResponse, query)
                        }
                        validatedResponse?.takeIf { deadline.remainingMillis() > 0L }
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
            if (!sendResolvedResponseIfCurrent(dnsPacket, dnsState, sharedResponse, outputStream)) {
                sendServFailResponse(dnsPacket, outputStream)
                return
            }
            recordResolvedQuery()
            addDnsQueryLog {
                "✓ 解析成功 [ID=${formatTxId(dnsPayload)}]: $domain (${sharedResponse.size} bytes)"
            }
        } else {
            sendServFailResponse(dnsPacket, outputStream)
            if (isUiForeground || backgroundFailureLogLimiter.tryAcquire()) {
                addDnsQueryLog(important = true) {
                    "✗ 請求失敗 [ID=${formatTxId(dnsPayload)}]: $domain 伺服器逾時、超載或無回應"
                }
            }
        }
    }

    private suspend fun resolveUpstreamQuery(
        dnsPayload: ByteArray,
        query: ParsedDnsQuery,
        domain: String,
        dnsState: DnsStateSnapshot,
        deadline: DnsRequestDeadline
    ): ByteArray? {
        val endpoints = DohEndpointConfiguration.endpoints(dnsState.server)
        val outcome = DnsTransportPolicy.resolve(
            allowPlaintextFallback = dnsState.server.allowPlaintextFallback,
            endpoints = endpoints,
            deadline = deadline,
            dohQuery = { endpoint ->
                if (!dohFailureBackoff.tryAcquire(endpoint.url)) {
                    null
                } else {
                    val response = try {
                        performDohLookup(endpoint, endpoints, query, deadline)
                    } catch (exception: CancellationException) {
                        dohFailureBackoff.cancelAttempt(endpoint.url)
                        throw exception
                    } catch (exception: Exception) {
                        dohFailureBackoff.recordFailure(endpoint.url)
                        logDnsTransportFailure("DoH resolution failed for ${endpoint.url}", exception)
                        null
                    }
                    if (response == null) {
                        dohFailureBackoff.recordFailure(endpoint.url)
                    } else {
                        dohFailureBackoff.recordSuccess(endpoint.url)
                    }
                    response
                }
            },
            udpQuery = {
                if (!dnsState.server.allowPlaintextFallback ||
                    !plaintextFallbackFence.allows(dnsState.server.id) ||
                    !isCurrentDnsState(dnsState) ||
                    deadline.remainingMillis() <= 0L
                ) {
                    null
                } else {
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
                            add(createDnsUdpEndpoint(dnsState.server.primaryIp))
                            dnsState.server.secondaryIp?.let { address ->
                                add(createDnsUdpEndpoint(address))
                            }
                        }
                        DnsUdpUpstreamClient.queryWithFallback(socket, query, upstreams, deadline)
                    } finally {
                        socket.close()
                    }
                }
            }
        )

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
            DnsTransport.UNAVAILABLE -> {
                dnsTransportStatusFlow.value = if (dnsState.server.allowPlaintextFallback) {
                    "上游不可用 · SERVFAIL"
                } else {
                    "僅加密 · DoH 不可用 · SERVFAIL"
                }
            }
        }
        return outcome.response?.takeIf { deadline.remainingMillis() > 0L }
    }

    private fun createDnsUdpEndpoint(ip: String): DnsUdpUpstreamEndpoint {
        val address = InetAddress.getByName(ip)
        val port = if (
            BuildConfig.APPLICATION_ID.endsWith(".d08test") && address.isLoopbackAddress
        ) {
            BuildConfig.DNS_UDP_PORT
        } else {
            53
        }
        return DnsUdpUpstreamEndpoint(address, port)
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

    private fun stopSelfIfIdle(startId: Int) {
        if (
            lifecycleStateFlow.value == VpnLifecycleState.STOPPED ||
            lifecycleStateFlow.value == VpnLifecycleState.FAILED
        ) {
            stopSelfResult(startId)
        }
    }

    private fun notificationText(state: VpnLifecycleState): String = when (state) {
        VpnLifecycleState.STOPPED -> "DNS Shield 防護已關閉"
        VpnLifecycleState.STARTING -> "DNS Shield 正在啟動防護…"
        VpnLifecycleState.RUNNING -> "DNS Shield 防護中"
        VpnLifecycleState.STOPPING -> "DNS Shield 正在停止防護…"
        VpnLifecycleState.FAILED -> "DNS Shield 防護異常"
    }

    // Service destruction cannot suspend, so it closes the owned descriptor and cancels its session directly.
    private fun closeTunnelResources() {
        rulePolicyStatusFlow.value = RulePolicyStatus.NotLoaded
        val finalState = lifecycleStateFlow.value.stateAfterServiceDestroy()
        tunnelGeneration++
        if (finalState != VpnLifecycleState.FAILED) {
            updateLifecycleState(VpnLifecycleState.STOPPING)
        }
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

        try {
            sessionJob?.cancelAndJoin()
        } catch (exception: CancellationException) {
            throw exception
        } catch (exception: Exception) {
            Log.e(TAG, "Exception cancelling tunnel session during shutdown", exception)
        }

        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (exception: Exception) {
            Log.e(TAG, "Error stopping foreground service", exception)
        }

        updateLifecycleState(finalState)
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
