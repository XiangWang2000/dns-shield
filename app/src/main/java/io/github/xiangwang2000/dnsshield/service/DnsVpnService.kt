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
import android.util.Log
import androidx.core.app.NotificationCompat
import io.github.xiangwang2000.dnsshield.MainActivity
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import kotlin.coroutines.resume
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.sync.Semaphore
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
        private const val MAX_LOG_LINES = 100
        private const val FOREGROUND_LOG_FLUSH_MS = 300L
        private const val FOREGROUND_STATS_FLUSH_MS = 500L
        private const val MEMORY_TRIM_CLEAR_CACHE_LEVEL = 60

        const val VPN_IP = "10.0.0.2"
        const val DUMMY_DNS_IP = "10.0.0.1"

        // Static status flows for real-time UI tracking
        val isRunningFlow = MutableStateFlow(false)
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

        // In-memory DNS cache structure with zero-allocation query keys and parsed response TTLs
        class DnsQueryKey(
            val bytes: ByteArray,
            private val resolverGeneration: Int,
            private val policyGeneration: Int
        ) {
            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is DnsQueryKey) return false
                if (resolverGeneration != other.resolverGeneration) return false
                if (policyGeneration != other.policyGeneration) return false
                if (bytes.size != other.bytes.size) return false
                for (i in 2 until bytes.size) {
                    if (bytes[i] != other.bytes[i]) return false
                }
                return true
            }

            override fun hashCode(): Int {
                var result = 31 * resolverGeneration + policyGeneration
                for (i in 2 until bytes.size) {
                    result = 31 * result + bytes[i]
                }
                return result
            }

            fun copyForStorage() = DnsQueryKey(
                bytes = bytes.copyOf(),
                resolverGeneration = resolverGeneration,
                policyGeneration = policyGeneration
            )
        }

        class CachedDnsRecord(val responseData: ByteArray, val expireAt: Long)
        private val dnsCache = LruCache<DnsQueryKey, CachedDnsRecord>(500)
        private val blockDecisionCache = LruCache<String, Boolean>(1024)

        // Thread-safe singleton lock for OkHttpClient
        @Volatile private var okHttpClientInstance: OkHttpClient? = null

        fun getOkHttpClient(): OkHttpClient {
            return okHttpClientInstance ?: synchronized(this) {
                okHttpClientInstance ?: OkHttpClient.Builder()
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
        fun putCache(key: DnsQueryKey, responseData: ByteArray) {
            if (key.bytes.size < 2) return
            val ttlMillis = parseDnsResponseTtl(responseData)
            val expireAt = System.currentTimeMillis() + ttlMillis
            val record = CachedDnsRecord(responseData.copyOf(), expireAt)
            dnsCache.put(key.copyForStorage(), record)
        }

        fun getCache(key: DnsQueryKey, dnsPayload: ByteArray): ByteArray? {
            if (dnsPayload.size < 2) return null
            val record = dnsCache.get(key)
            if (record != null) {
                if (System.currentTimeMillis() < record.expireAt) {
                    return copyResponseWithTxId(record.responseData, dnsPayload)
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

        fun addDnsQueryLog(important: Boolean = false, message: () -> String) {
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
            if (dnsPayload.size < 12) return "Unknown"
            val sb = java.lang.StringBuilder()
            var pos = 12
            try {
                while (pos < dnsPayload.size) {
                    val len = dnsPayload[pos].toInt() and 0xFF
                    if (len == 0) break
                    if ((len and 0xC0) == 0xC0) {
                        // Compressed label check marker
                        sb.append("[compressed]")
                        break
                    }
                    if (pos + 1 + len > dnsPayload.size) break
                    if (sb.isNotEmpty()) {
                        sb.append('.')
                    }
                    sb.append(String(dnsPayload, pos + 1, len, java.nio.charset.StandardCharsets.US_ASCII))
                    pos += 1 + len
                }
            } catch (e: Exception) {
                return "Unknown"
            }
            return if (sb.isEmpty()) "Unknown" else sb.toString()
        }

        object AdDomainMatcher {
            private val exactBlocks = setOf(
                "doubleclick.net", "admob.com", "pagead2.googlesyndication.com",
                "googleads.g.doubleclick.net", "analytics.google.com", "crashlytics.com"
            )

            private val suffixBlocks = listOf(
                ".doubleclick.net", ".admob.com", ".analytics.google.com",
                ".adnxs.com", ".adcolony.com", ".adservice.google.com",
                ".scorecardresearch.com", ".hotjar.com", ".telemetry.mozilla.org",
                ".adjust.com", ".appsflyer.com"
            )

            private val containsBlocks = listOf(
                "adservice", "adsystem", "googleads", "pagead", "amazon-adsystem",
                "telemetry-", "analytics-"
            )

            private val exactBlockedKeywords = setOf(
                "ads", "tracker", "telemetry", "analytics", "crashlytics"
            )

            fun shouldBlock(domain: String): Boolean {
                val lowercase = domain.lowercase().trim()
                if (lowercase.isEmpty() || lowercase == "unknown") return false
                blockDecisionCache.get(lowercase)?.let { return it }

                // 1. Exact match checking
                if (exactBlocks.contains(lowercase)) {
                    blockDecisionCache.put(lowercase, true)
                    return true
                }

                // 2. Suffix match checking
                for (suffix in suffixBlocks) {
                    if (lowercase.endsWith(suffix)) {
                        blockDecisionCache.put(lowercase, true)
                        return true
                    }
                }

                // 3. Substring contains checking (careful with parts)
                for (part in containsBlocks) {
                    if (lowercase.contains(part)) {
                        blockDecisionCache.put(lowercase, true)
                        return true
                    }
                }

                // 4. Exact split keyword checking (e.g., ads.example.com or any subdomain being strictly equal to the keyword)
                val parts = lowercase.split('.')
                for (part in parts) {
                    if (exactBlockedKeywords.contains(part)) {
                        blockDecisionCache.put(lowercase, true)
                        return true
                    }
                }

                blockDecisionCache.put(lowercase, false)
                return false
            }
        }

        fun isAdOrTracker(domain: String): Boolean {
            return AdDomainMatcher.shouldBlock(domain)
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
            val response = dnsPayload.clone()
            if (response.size >= 12) {
                val rd = response[2].toInt() and 0x01
                response[2] = (0x80 or rd).toByte() // QR=1, preserve rd
                response[3] = 0x83.toByte()         // RA=1, RCODE=3 (NXDOMAIN)

                // Zero out answer, authority and additional resource counts
                response[6] = 0x00
                response[7] = 0x00
                response[8] = 0x00
                response[9] = 0x00
                response[10] = 0x00
                response[11] = 0x00
            }
            return response
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(serviceJob + Dispatchers.IO)

    private data class DnsStateSnapshot(
        val primary: String,
        val secondary: String?,
        val resolverGeneration: Int,
        val policyGeneration: Int
    )

    private val dnsStateLock = Any()
    private var resolverGeneration = 0
    private var policyGeneration = 0
    private val inFlightQueries = ConcurrentHashMap<DnsQueryKey, CompletableDeferred<ByteArray?>>()

    // Explicit, clean separation of VPN active running components from the general ServiceScope
    private var tunnelParentJob: Job? = null
    private var tunnelScope: CoroutineScope? = null

    // Robust local concurrency throttle to reduce background burst pressure on CPU and radio.
    private val querySemaphore = Semaphore(MAX_CONCURRENT_DNS_QUERIES)

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
            policyGeneration++
            clearDnsStateLocked()
        }
    }

    private fun clearDnsStateLocked() {
        dnsCache.evictAll()
        inFlightQueries.clear()
        blockDecisionCache.evictAll()
    }

    private fun snapshotDnsState(): DnsStateSnapshot = synchronized(dnsStateLock) {
        DnsStateSnapshot(
            primary = upstreamDnsPrimary,
            secondary = upstreamDnsSecondary,
            resolverGeneration = resolverGeneration,
            policyGeneration = policyGeneration
        )
    }

    private fun isCurrentDnsState(state: DnsStateSnapshot): Boolean = synchronized(dnsStateLock) {
        resolverGeneration == state.resolverGeneration && policyGeneration == state.policyGeneration
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
                invalidatePolicyState()
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
        // Parse IPv4 packet length & properties
        val version = (packet[0].toInt() shr 4) and 0x0F
        if (version != 4) return // We only handle IPv4

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl) return

        val protocol = packet[9].toInt() and 0xFF

        // Protocol 17 = UDP
        if (protocol != 17) return

        // Verify the UDP header fits
        val udpOffset = ihl
        if (length < udpOffset + 8) return

        // Parse UDP Ports
        val srcPort = ((packet[udpOffset].toInt() and 0xFF) shl 8) or (packet[udpOffset + 1].toInt() and 0xFF)
        val dstPort = ((packet[udpOffset + 2].toInt() and 0xFF) shl 8) or (packet[udpOffset + 3].toInt() and 0xFF)

        // Check if destination port is 53 (DNS)
        if (dstPort == 53) {
            val udpLength = ((packet[udpOffset + 4].toInt() and 0xFF) shl 8) or (packet[udpOffset + 5].toInt() and 0xFF)
            val payloadLength = udpLength - 8
            if (payloadLength <= 0 || length < udpOffset + 8 + payloadLength) return

            val dnsPayload = ByteArray(payloadLength)
            System.arraycopy(packet, udpOffset + 8, dnsPayload, 0, payloadLength)

            // Capture source IP and destination IP to respond with exact routing
            val sourceIp = ByteArray(4)
            System.arraycopy(packet, 12, sourceIp, 0, 4) // client IP
            val destIp = ByteArray(4)
            System.arraycopy(packet, 16, destIp, 0, 4) // mock DNS server IP (10.0.0.1)

            // Forward the DNS query asynchronously under the dedicated tunnelScope
            val activeScope = tunnelScope
            if (activeScope != null && activeScope.isActive) {
                activeScope.launch {
                    try {
                        forwardDnsQuery(dnsPayload, sourceIp, destIp, srcPort, outputStream)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed in DNS query coroutine", e)
                    }
                }
            }
        }
    }

    private suspend fun performDohLookup(
        dohUrl: String,
        dnsPayload: ByteArray
    ): ByteArray? {
        val mediaType = "application/dns-message".toMediaType()
        val requestBody = dnsPayload.toRequestBody(mediaType)

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
                        Log.e(TAG, "DoH resolution failed for $dohUrl", e)
                        continuation.resume(null)
                    }
                }

                override fun onResponse(call: okhttp3.Call, response: okhttp3.Response) {
                    try {
                        if (continuation.isActive) {
                            if (response.isSuccessful) {
                                val bytes = response.body.bytes()
                                continuation.resume(bytes)
                            } else {
                                Log.e(TAG, "DoH resolution error: HTTP ${response.code} for $dohUrl")
                                continuation.resume(null)
                            }
                        } else {
                            response.close()
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed reading DoH body bytes", e)
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
        outputStream: FileOutputStream
    ) {
        val responseIpPacket = buildUdpIpPacket(
            srcIp = mockDnsIp, // 10.0.0.1
            dstIp = clientIp,   // Client IP
            srcPort = 53,
            dstPort = clientPort,
            payload = responseData
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
        clientIp: ByteArray,
        mockDnsIp: ByteArray,
        clientPort: Int,
        outputStream: FileOutputStream
    ) {
        val dnsState = snapshotDnsState()
        val queryKey = DnsQueryKey(
            bytes = dnsPayload,
            resolverGeneration = dnsState.resolverGeneration,
            policyGeneration = dnsState.policyGeneration
        )

        // 1. Return known-good cached responses before doing domain parsing or block matching.
        val cachedResponse = getCache(queryKey, dnsPayload)
        if (cachedResponse != null) {
            sendResponsePacket(cachedResponse, clientIp, mockDnsIp, clientPort, outputStream)

            recordResolvedQuery()

            addDnsQueryLog {
                val domain = parseDomainName(dnsPayload)
                "⚡ [快取解析] [ID=${formatTxId(dnsPayload)}]: $domain (記憶體命中, ${cachedResponse.size} bytes)"
            }
            return
        }

        val domain = parseDomainName(dnsPayload)

        // 2. Check if ad domain / tracker - BLOCK IMMEDIATELY with genuine NXDOMAIN synthesis
        val isAd = isAdOrTracker(domain)
        if (isAd) {
            val blockedResponse = buildNxDomainResponse(dnsPayload)
            sendResponsePacket(blockedResponse, clientIp, mockDnsIp, clientPort, outputStream)

            val savedInBytes = estimateSavedBytes(domain)
            recordBlockedQuery(savedInBytes)

            addDnsQueryLog(important = true) {
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
                    resolveUpstreamQuery(dnsPayload, domain, dnsState)
                }
                if (response != null && isCurrentDnsState(dnsState)) {
                    putCache(queryKey, response)
                }
                leaderResult.complete(response)
                response
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

        // 4. Every client receives its own response copy and transaction ID.
        if (sharedResponse != null) {
            val responseForClient = copyResponseWithTxId(sharedResponse, dnsPayload)
            sendResponsePacket(responseForClient, clientIp, mockDnsIp, clientPort, outputStream)

            recordResolvedQuery()

            addDnsQueryLog {
                "✓ 解析成功 [ID=${formatTxId(dnsPayload)}]: $domain (${responseForClient.size} bytes)"
            }
        } else {
            addDnsQueryLog(important = true) {
                "✗ 請求失敗 [ID=${formatTxId(dnsPayload)}]: $domain 伺服器逾時或無回應"
            }
        }
    }

    private suspend fun resolveUpstreamQuery(
        dnsPayload: ByteArray,
        domain: String,
        dnsState: DnsStateSnapshot
    ): ByteArray? {
        var responseData: ByteArray? = null
        val primaryDoHUrl = getDoHUrl(dnsState.primary)

        if (primaryDoHUrl != null) {
            responseData = performDohLookup(primaryDoHUrl, dnsPayload)
            if (responseData != null) {
                addDnsQueryLog {
                    "🌐 [DoH 解析] [ID=${formatTxId(dnsPayload)}]: 透過安全 HTTPS 連線成功解析 $domain"
                }
            }
        }

        // Fallback to UDP if DoH is not applicable or failed.
        if (responseData == null) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                protect(socket)
                socket.soTimeout = 3000

                val primaryAddress = InetAddress.getByName(dnsState.primary)
                var responsePacket = resolveQuery(socket, dnsPayload, primaryAddress)

                if (responsePacket == null && dnsState.secondary != null) {
                    val secondaryAddress = InetAddress.getByName(dnsState.secondary)
                    responsePacket = resolveQuery(socket, dnsPayload, secondaryAddress)
                }

                if (responsePacket != null) {
                    responseData = responsePacket.data.copyOf(responsePacket.length)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Standard UDP resolution fallback exception", e)
            } finally {
                socket?.close()
            }
        }
        return responseData
    }

    private fun formatTxId(dnsPayload: ByteArray): String {
        return if (dnsPayload.size >= 2) {
            String.format("0x%02X%02X", dnsPayload[0], dnsPayload[1])
        } else {
            "Unknown"
        }
    }

    private fun resolveQuery(
        socket: DatagramSocket,
        dnsPayload: ByteArray,
        dnsServer: InetAddress
    ): DatagramPacket? {
        val recvBuffer = ByteArray(4096)
        try {
            val sendPacket = DatagramPacket(dnsPayload, dnsPayload.size, dnsServer, 53)
            socket.send(sendPacket)

            val recvPacket = DatagramPacket(recvBuffer, recvBuffer.size)
            socket.receive(recvPacket)
            return recvPacket
        } catch (e: Exception) {
            Log.e(TAG, "DNS lookup failed on ${dnsServer.hostAddress}", e)
            return null
        }
    }

    private fun buildUdpIpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val ipHeaderLength = 20
        val udpHeaderLength = 8
        val totalLength = ipHeaderLength + udpHeaderLength + payload.size

        val packet = ByteArray(totalLength)

        // --- IPv4 Header ---
        packet[0] = 0x45.toByte() // IP Version (4) + IHL (5 words = 20 bytes)
        packet[1] = 0x00.toByte() // ToS / DSCP
        packet[2] = ((totalLength shr 8) and 0xFF).toByte() // Total length MSB
        packet[3] = (totalLength and 0xFF).toByte()        // Total length LSB
        packet[4] = 0x00.toByte() // Identification MSB
        packet[5] = 0x00.toByte() // Identification LSB
        packet[6] = 0x40.toByte() // Flags: Don't Fragment (0x4000)
        packet[7] = 0x00.toByte() // Fragment Offset LSB
        packet[8] = 64.toByte()   // TTL
        packet[9] = 17.toByte()   // Protocol UDP is 17
        packet[10] = 0x00.toByte() // Checksum placeholder MSB
        packet[11] = 0x00.toByte() // Checksum placeholder LSB

        // Source & Destination IPs
        System.arraycopy(srcIp, 0, packet, 12, 4)
        System.arraycopy(dstIp, 0, packet, 16, 4)

        // Calculate and write IPv4 header Checksum
        val ipChecksum = calculateChecksum(packet, 0, ipHeaderLength)
        packet[10] = ((ipChecksum shr 8) and 0xFF).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        // --- UDP Header ---
        val udpOffset = ipHeaderLength
        packet[udpOffset] = ((srcPort shr 8) and 0xFF).toByte()     // Source Port MSB
        packet[udpOffset + 1] = (srcPort and 0xFF).toByte()         // Source Port LSB
        packet[udpOffset + 2] = ((dstPort shr 8) and 0xFF).toByte() // Destination Port MSB
        packet[udpOffset + 3] = (dstPort and 0xFF).toByte()         // Destination Port LSB

        val udpLen = udpHeaderLength + payload.size
        packet[udpOffset + 4] = ((udpLen shr 8) and 0xFF).toByte()  // UDP Length MSB
        packet[udpOffset + 5] = (udpLen and 0xFF).toByte()          // UDP Length LSB

        packet[udpOffset + 6] = 0x00.toByte() // UDP Checksum (can be omitted in IPv4 UDP)
        packet[udpOffset + 7] = 0x00.toByte()

        // --- UDP Payload ---
        System.arraycopy(payload, 0, packet, udpOffset + udpHeaderLength, payload.size)

        return packet
    }

    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length

        while (i < end - 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    // Gracefully and synchronously shutdown tunnel resources to prevent leakage
    private fun closeTunnelResources() {
        isVpnRunning = false
        isRunningFlow.value = false

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
