package io.github.xiangwang2000.dnsshield.service

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
import android.util.Log
import androidx.core.app.NotificationCompat
import io.github.xiangwang2000.dnsshield.MainActivity
import io.github.xiangwang2000.dnsshield.blocking.CompiledBlocklistStatus
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyAssembly
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyCacheKey
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyDiagnostics
import io.github.xiangwang2000.dnsshield.blocking.ProductionBlocklistAssetLoader
import io.github.xiangwang2000.dnsshield.blocking.PublicSuffixResolverOwner
import io.github.xiangwang2000.dnsshield.blocking.ReloadableDomainPolicy
import io.github.xiangwang2000.dnsshield.blocking.RuntimeDomainPolicy
import io.github.xiangwang2000.dnsshield.data.AppDatabase
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
import java.util.concurrent.ConcurrentHashMap
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
        private const val NETWORK_CHANGE_DEBOUNCE_MS = 500L
        private const val NETWORK_CHANGE_POLL_MS = 25L

        const val VPN_IP = "10.0.0.2"
        const val DUMMY_DNS_IP = "10.0.0.1"

        // Publish one lifecycle state for the UI and service notification.
        val lifecycleStateFlow = MutableStateFlow(VpnLifecycleState.STOPPED)
        val queryCountFlow = MutableStateFlow(0)
        val blockedAdsFlow = MutableStateFlow(0)
        val savedBytesFlow = MutableStateFlow(0L)
        val activeDnsFlow = MutableStateFlow("None")
        val liveLogsFlow = MutableStateFlow<List<String>>(emptyList())

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

        class CachedDnsRecord(val responseData: ByteArray, val expireAt: Long)
        private val dnsCache = LruCache<DnsQueryKey, CachedDnsRecord>(500)
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
            return when (ip) {
                "8.8.8.8", "8.8.4.4" -> "https://dns.google/dns-query"
                "1.1.1.1", "1.0.0.1" -> "https://cloudflare-dns.com/dns-query"
                "94.140.14.14", "94.140.15.15" -> "https://dns.adguard-dns.com/dns-query"
                "9.9.9.9", "149.112.112.112" -> "https://dns.quad9.net/dns-query"
                else -> null
            }
        }

        fun parseDnsResponseTtl(response: ByteArray): Long {
            try {
                if (response.size < 12) return 10_000L // 10s fallback for small packets
                val qdCount = ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF)
                val anCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)

                var index = 12

                // Skip Questions to find Answers offset
                for (i in 0 until qdCount) {
                    index = skipName(response, index)
                    index += 4 // QTYPE (2) + QCLASS (2)
                    if (index > response.size) return 10_000L
                }

                var minTtlSec = Long.MAX_VALUE
                for (i in 0 until anCount) {
                    index = skipName(response, index)
                    if (index + 10 > response.size) break

                    // index points to TYPE (2 bytes)
                    index += 4 // Skip TYPE and CLASS

                    val ttl = ((response[index].toLong() and 0xFF) shl 24) or
                              ((response[index + 1].toLong() and 0xFF) shl 16) or
                              ((response[index + 2].toLong() and 0xFF) shl 8) or
                              (response[index + 3].toLong() and 0xFF)
                    index += 4

                    val rdLength = ((response[index].toInt() and 0xFF) shl 8) or (response[index + 1].toInt() and 0xFF)
                    index += 2 + rdLength

                    if (ttl > 0) {
                        if (ttl < minTtlSec) {
                            minTtlSec = ttl
                        }
                    }
                }

                if (minTtlSec != Long.MAX_VALUE) {
                    // Safe boundaries: clamp between 5 seconds (avoid flood) and 300 seconds (avoid outdated IPs)
                    val finalTtlSec = minTtlSec.coerceIn(5, 300)
                    return finalTtlSec * 1000L
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error parsing DNS response TTL", e)
            }
            return 30_000L // 30s default fallback
        }

        private fun skipName(data: ByteArray, startOffset: Int): Int {
            var index = startOffset
            while (index < data.size) {
                val len = data[index].toInt() and 0xFF
                if (len == 0) {
                    return index + 1
                } else if ((len and 0xC0) == 0xC0) {
                    return index + 2
                } else {
                    index += 1 + len
                }
            }
            return data.size
        }

        // Defensive copy added to protect LRU cache keys and records from mutable buffer modifications
        private fun putCache(key: DnsQueryKey, responseData: ByteArray) {
            if (key.byteCount < 2) return
            val ttlMillis = parseDnsResponseTtl(responseData)
            val expireAt = System.currentTimeMillis() + ttlMillis
            val record = CachedDnsRecord(responseData.copyOf(), expireAt)
            dnsCache.put(key.copyForStorage(), record)
        }

        private fun getCache(key: DnsQueryKey): ByteArray? {
            if (key.byteCount < 2) return null
            val record = dnsCache.get(key)
            if (record != null) {
                if (System.currentTimeMillis() < record.expireAt) {
                    return record.responseData
                } else {
                    dnsCache.remove(key)
                }
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
            dnsCache.evictAll()
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
    private val userIntentStore by lazy {
        VpnUserIntentStore(
            getSharedPreferences("vpn_service_state", Context.MODE_PRIVATE)
        )
    }
    private var latestLifecycleStartId = 0

    private sealed class LifecycleCommand {
        data class Start(val startId: Int, val requestGeneration: Long) : LifecycleCommand()
        data class Stop(val startId: Int) : LifecycleCommand()
        data class Restart(val startId: Int, val requestGeneration: Long) : LifecycleCommand()
        data class UpdateDns(
            val startId: Int,
            val primary: String,
            val secondary: String?,
            val dnsName: String
        ) : LifecycleCommand()
        data class ClearLogs(val startId: Int) : LifecycleCommand()
        data class TunnelEnded(
            val generation: Long,
            val descriptor: ParcelFileDescriptor,
            val failure: String?
        ) : LifecycleCommand()
    }

    private data class DnsStateSnapshot(
        val primary: String,
        val secondary: String?,
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

    private fun reloadDomainPolicy() {
        val status = try {
            val assembly = RuntimeDomainPolicy.assemble(
                filesDirectory = filesDir,
                loadBundledBlocklist = productionBlocklistLoader::load,
                registrableDomainResolverProvider = {
                    publicSuffixResolverOwner.resolverOrNull()
                }
            )
            domainPolicy.install(assembly) {
                invalidatePolicyState()
            }
        } catch (exception: Exception) {
            val reason = exception.message?.takeIf(String::isNotBlank)
                ?: exception.javaClass.simpleName
            Log.e(TAG, "Failed to reload domain policy", exception)
            addLog("[攔截規則] 重新載入失敗，保留目前規則：$reason")
            return
        }

        addLog(DomainPolicyDiagnostics.message(status))
    }

    private fun clearDnsStateLocked() {
        clearDnsAnswerCacheLocked()
        blockDecisionCache.evictAll()
    }

    private fun clearDnsAnswerCacheLocked() {
        dnsCache.evictAll()
    }

    private fun snapshotDnsState(): DnsStateSnapshot = synchronized(dnsStateLock) {
        DnsStateSnapshot(
            primary = upstreamDnsPrimary,
            secondary = upstreamDnsSecondary,
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
            registration.bestMatchingCallback?.let { callback ->
                manager.registerBestMatchingNetworkCallback(request, callback, Handler(Looper.getMainLooper()))
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
        val primary = synchronized(dnsStateLock) { upstreamDnsPrimary }
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
                        updateResolverState(command.primary, command.secondary)
                        activeDnsFlow.value = command.dnsName + " (" + command.primary + ")"
                        addLog(
                            "[DNS 變更同步] 已即時套用新 DNS 設定：" +
                                command.dnsName + " (" + command.primary + ")"
                        )
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
                val primary = intent.getStringExtra("primary") ?: "8.8.8.8"
                val secondary = intent.getStringExtra("secondary")
                val dnsName = intent.getStringExtra("dnsName") ?: "Google DNS"
                lifecycleCommands.trySend(
                    LifecycleCommand.UpdateDns(startId, primary, secondary, dnsName)
                )
            }
            ACTION_CLEAR_LOGS -> {
                lifecycleCommands.trySend(LifecycleCommand.ClearLogs(startId))
            }
            null -> {
                val userIntent = userIntentStore.snapshot()
                if (userIntent.shouldRecoverFromSystemStart()) {
                    addLog("System recovery command received; restoring the requested VPN state")
                    val requestGeneration = lifecycleRequests.nextRequest()
                    lifecycleCommands.trySend(LifecycleCommand.Start(startId, requestGeneration))
                }
            }
        }
        return if (userIntentStore.snapshot().shouldUseStickyServiceStart()) {
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

            withContext(Dispatchers.IO) { reloadDomainPolicy() }
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
            val primary = activeServer?.primaryIp ?: "8.8.8.8"
            val secondary = activeServer?.secondaryIp
            updateResolverState(primary, secondary)
            val dnsName = activeServer?.name ?: "Google DNS"
            activeDnsFlow.value = "$dnsName ($primary)"
            addLog("Database loaded. Upstream DNS: " + dnsName + " (" + primary + ")")
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
                    underlyingNetworkGeneration = dnsState.underlyingNetworkGeneration,
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
                val networkCancellationResponseSent = AtomicBoolean(false)
                val requestJob = activeScope.launch(start = CoroutineStart.LAZY) {
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
                        if (isVpnRunning && activeScope.isActive && !isCurrentDnsState(dnsState)) {
                            if (lease.isLeader) queryAdmission.completeLeader(lease, null)
                            if (networkCancellationResponseSent.compareAndSet(false, true)) {
                                sendServFailResponse(dnsPacket, outputStream)
                            }
                        } else {
                            throw exception
                        }
                    } catch (exception: Exception) {
                        Log.e(TAG, "Failed in DNS query coroutine", exception)
                        if (lease.isLeader) queryAdmission.completeLeader(lease, null)
                        sendServFailResponse(dnsPacket, outputStream)
                    }
                }
                if (lease.isLeader) activeDnsLeaders[requestJob] = dnsState
                requestJob.invokeOnCompletion {
                    activeDnsLeaders.remove(requestJob)
                    if (lease.isLeader) queryAdmission.completeLeader(lease, null)
                    queryAdmission.release(lease)
                    if (
                        it is CancellationException &&
                        lease.isLeader &&
                        isVpnRunning &&
                        activeScope.isActive &&
                        !isCurrentDnsState(dnsState) &&
                        networkCancellationResponseSent.compareAndSet(false, true)
                    ) {
                        sendServFailResponse(dnsPacket, outputStream)
                    }
                }
                requestJob.start()
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
        var resolvedCacheHit = false
        val cachedResponse = try {
            synchronized(dnsStateLock) {
                if (isCurrentDnsStateLocked(dnsState)) {
                    getCache(queryKey)?.also { response ->
                        sendResponsePacket(
                            response,
                            dnsPacket.sourceIp,
                            dnsPacket.destinationIp,
                            dnsPacket.sourcePort,
                            outputStream,
                            transactionIdSource = dnsPacket.payload
                        )
                        resolvedCacheHit = true
                    }
                } else {
                    null
                }
            }
        } catch (exception: Exception) {
            Log.e(TAG, "Failed to read DNS cache", exception)
            sendServFailResponse(dnsPacket, outputStream)
            return true
        }
        if (resolvedCacheHit && cachedResponse != null) {
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
        if (!isBlocked) {
            if (!isCurrentDnsState(dnsState)) {
                sendServFailResponse(dnsPacket, outputStream)
                return true
            }
            return false
        }

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

    private fun sendServFailResponse(
        dnsPacket: ParsedIpv4UdpDnsQuery,
        outputStream: FileOutputStream
    ) {
        recordNetworkRecoveryFailure()
        sendResponsePacket(
            responseData = DnsMessageValidator.buildServFailResponse(dnsPacket.query),
            clientIp = dnsPacket.sourceIp,
            mockDnsIp = dnsPacket.destinationIp,
            clientPort = dnsPacket.sourcePort,
            outputStream = outputStream
        )
    }

    private fun putCacheIfCurrentState(
        dnsState: DnsStateSnapshot,
        queryKey: DnsQueryKey,
        response: ByteArray
    ): Boolean = synchronized(dnsStateLock) {
        if (!isCurrentDnsStateLocked(dnsState)) {
            false
        } else {
            putCache(queryKey, response)
            true
        }
    }

    private fun sendResolvedResponseIfCurrent(
        dnsPacket: ParsedIpv4UdpDnsQuery,
        dnsState: DnsStateSnapshot,
        response: ByteArray,
        outputStream: FileOutputStream
    ): Boolean = synchronized(dnsStateLock) {
        if (!isCurrentDnsStateLocked(dnsState)) {
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

    private suspend fun performDohLookup(
        dohUrl: String,
        query: ParsedDnsQuery,
        deadline: DnsRequestDeadline
    ): ByteArray? {
        val remainingMillis = deadline.remainingMillis()
        if (remainingMillis <= 0L) return null

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
        if (!isCurrentDnsState(dnsState)) {
            if (lease.isLeader) queryAdmission.completeLeader(lease, null)
            sendServFailResponse(dnsPacket, outputStream)
            return
        }
        if (lease.isLeader && !awaitStableUnderlyingNetwork(dnsState, deadline)) {
            queryAdmission.completeLeader(lease, null)
            sendServFailResponse(dnsPacket, outputStream)
            return
        }
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
                            DnsMessageValidator.isCacheableResponse(validatedResponse, query) &&
                            !putCacheIfCurrentState(dnsState, queryKey, validatedResponse)
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

        if (sharedResponse != null && sendResolvedResponseIfCurrent(
                dnsPacket = dnsPacket,
                dnsState = dnsState,
                response = sharedResponse,
                outputStream = outputStream
            )
        ) {
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
        val primaryDoHUrl = getDoHUrl(dnsState.primary)
        return DnsTransportFallback.resolve(
            deadline = deadline,
            primary = {
                if (
                    primaryDoHUrl == null ||
                    !isCurrentDnsState(dnsState) ||
                    !dohFailureBackoff.tryAcquire(primaryDoHUrl, dnsState.underlyingNetworkGeneration)
                ) {
                    null
                } else {
                    val response = try {
                        performDohLookup(primaryDoHUrl, query, deadline)
                    } catch (exception: CancellationException) {
                        dohFailureBackoff.cancelAttempt(primaryDoHUrl, dnsState.underlyingNetworkGeneration)
                        throw exception
                    } catch (exception: Exception) {
                        dohFailureBackoff.recordFailure(primaryDoHUrl, dnsState.underlyingNetworkGeneration)
                        logDnsTransportFailure("DoH resolution failed for $primaryDoHUrl", exception)
                        null
                    }
                    if (response == null) {
                        dohFailureBackoff.recordFailure(primaryDoHUrl, dnsState.underlyingNetworkGeneration)
                    } else {
                        dohFailureBackoff.recordSuccess(primaryDoHUrl, dnsState.underlyingNetworkGeneration)
                        addDnsQueryLog {
                            "🌐 [DoH 解析] [ID=${formatTxId(dnsPayload)}]: 透過安全 HTTPS 連線成功解析 $domain"
                        }
                    }
                    response
                }
            },
            fallback = {
                if (deadline.remainingMillis() <= 0L || !isCurrentDnsState(dnsState)) {
                    null
                } else {
                    val socket = DatagramSocket()
                    try {
                        if (!protect(socket)) throw IOException("Failed to protect DNS UDP socket from the VPN.")
                        val upstreams = buildList {
                            add(DnsUdpUpstreamEndpoint(InetAddress.getByName(dnsState.primary)))
                            dnsState.secondary?.let { address ->
                                add(DnsUdpUpstreamEndpoint(InetAddress.getByName(address)))
                            }
                        }
                        DnsUdpUpstreamClient.queryWithFallback(socket, query, upstreams, deadline)
                    } finally {
                        socket.close()
                    }
                }
            }
        )?.takeIf { deadline.remainingMillis() > 0L && isCurrentDnsState(dnsState) }
    }

    private fun formatTxId(dnsPayload: ByteArray): String {
        return if (dnsPayload.size >= 2) {
            String.format("0x%02X%02X", dnsPayload[0], dnsPayload[1])
        } else {
            "Unknown"
        }
    }

    private suspend fun handleTunnelEnded(command: LifecycleCommand.TunnelEnded) {
        if (
            command.generation != tunnelGeneration ||
            vpnInterface !== command.descriptor ||
            lifecycleStateFlow.value != VpnLifecycleState.RUNNING
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
        unregisterUnderlyingNetworkCallback()
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
