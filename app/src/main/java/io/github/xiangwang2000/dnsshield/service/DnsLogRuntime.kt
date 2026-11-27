package io.github.xiangwang2000.dnsshield.service

import android.util.Log
import io.github.xiangwang2000.dnsshield.BuildConfig
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow

/** Process-scoped DNS logs and diagnostic snapshots, independent of VPN service instances. */
internal object DnsLogRuntime {
    private const val TAG = "DnsVpnService"
    private const val MAX_LOG_LINES = 100
    private const val FOREGROUND_LOG_FLUSH_MS = 300L
    private const val FOREGROUND_STATS_FLUSH_MS = 500L

    internal val diagnosticsFlow = MutableStateFlow(DnsDiagnosticsSnapshot())
    internal val liveLogsFlow = MutableStateFlow<List<String>>(emptyList())
    internal val liveDecisionEventsFlow = MutableStateFlow<List<DnsDecisionEvent>>(emptyList())

    private val diagnosticMetrics = DnsDiagnosticMetrics()
    private val flowFlushScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val flushLock = Any()
    private val logsDirty = AtomicBoolean(false)
    private val statsDirty = AtomicBoolean(false)

    @Volatile
    internal var isUiForeground = false
        private set

    @Volatile
    private var logFlushJob: Job? = null

    @Volatile
    private var statsFlushJob: Job? = null

    private val logList = mutableListOf<String>()
    private val decisionEvents = DnsDecisionEventBuffer(
        scope = flowFlushScope,
        capacity = MAX_LOG_LINES,
        publish = { liveDecisionEventsFlow.value = it }
    )

    internal fun resetDiagnostics() {
        diagnosticMetrics.reset()
        diagnosticsFlow.value = diagnosticMetrics.snapshot()
    }

    internal fun diagnosticsSnapshot(): DnsDiagnosticsSnapshot = diagnosticMetrics.snapshot()

    internal fun recordUdpTimeout(request: DnsDiagnosticMetrics.Request, isPrimary: Boolean) {
        diagnosticMetrics.recordUdpTimeout(request, isPrimary)
    }

    internal fun recordUdpAnswer(request: DnsDiagnosticMetrics.Request, isPrimary: Boolean) {
        diagnosticMetrics.recordUdpAnswer(request, isPrimary)
    }

    internal fun recordUdpPrimaryDeferred(request: DnsDiagnosticMetrics.Request) {
        diagnosticMetrics.recordUdpPrimaryDeferred(request)
    }

    internal fun setUiForeground(isForeground: Boolean) {
        synchronized(flushLock) {
            isUiForeground = isForeground
            decisionEvents.setForeground(isForeground)
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

    internal fun addLog(message: String) {
        addLogInternal(message, writeDebugLog = true)
    }

    internal inline fun addDnsQueryLog(important: Boolean = false, message: () -> String) {
        if (!important && !isUiForeground) return
        addLogInternal(message(), writeDebugLog = important || isUiForeground)
    }

    private fun addLogInternal(message: String, writeDebugLog: Boolean) {
        val timestamp = DnsLogFormatting.timestamp(System.currentTimeMillis())
        val formattedMessage = "[$timestamp] $message"
        // Release builds keep the in-app log but must not leak queried domains to logcat.
        if (writeDebugLog && BuildConfig.DEBUG) Log.d(TAG, formattedMessage)
        synchronized(logList) {
            logList.add(0, formattedMessage)
            if (logList.size > MAX_LOG_LINES) logList.removeAt(logList.size - 1)
        }
        scheduleLogFlush()
    }

    internal fun logDnsTransportFailure(message: String) {
        if (!isUiForeground) return
        Log.e(TAG, message)
    }

    internal fun clearLogs() {
        synchronized(logList) {
            logList.clear()
            if (isUiForeground) liveLogsFlow.value = emptyList()
        }
        diagnosticMetrics.reset()
        decisionEvents.clear()
        if (isUiForeground) flushStatsNow()
    }

    internal fun beginDnsRequest(receivedAtNanos: Long): DnsDiagnosticMetrics.Request =
        diagnosticMetrics.begin(receivedAtNanos).also { scheduleStatsFlush() }

    internal fun completeDnsRequest(request: DnsDiagnosticMetrics.Request, outcome: DnsClientTerminalOutcome) {
        if (diagnosticMetrics.complete(request, outcome)) scheduleStatsFlush()
    }

    internal fun recordCacheHit(request: DnsDiagnosticMetrics.Request) {
        diagnosticMetrics.recordCacheHit(request)
        scheduleStatsFlush()
    }

    internal fun recordCoalesced(request: DnsDiagnosticMetrics.Request) {
        diagnosticMetrics.recordCoalesced(request)
        scheduleStatsFlush()
    }

    internal fun recordOverload(request: DnsDiagnosticMetrics.Request) {
        diagnosticMetrics.recordOverload(request)
        scheduleStatsFlush()
    }

    internal fun recordTransportAttempt(
        request: DnsDiagnosticMetrics.Request,
        transport: DnsUpstreamTransport
    ) {
        diagnosticMetrics.recordTransportAttempt(request, transport)
        scheduleStatsFlush()
    }

    internal fun recordFallbackAttempt(request: DnsDiagnosticMetrics.Request) {
        diagnosticMetrics.recordFallbackAttempt(request)
        scheduleStatsFlush()
    }

    internal fun recordUdpRetryAttempt(request: DnsDiagnosticMetrics.Request) {
        diagnosticMetrics.recordUdpRetryAttempt(request)
        scheduleStatsFlush()
    }

    internal fun recordCoalescedWait(request: DnsDiagnosticMetrics.Request, elapsedNanos: Long) {
        diagnosticMetrics.recordCoalescedWait(request, elapsedNanos)
        scheduleStatsFlush()
    }

    internal fun recordDomainDecision(
        domain: String,
        reason: DnsDecisionReason,
        decision: DnsDecision = DnsDecision.BLOCK
    ) {
        decisionEvents.record(domain, reason, decision)
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
                    if (logsDirty.get()) scheduleLogFlush()
                }
            }
        }
    }

    private fun scheduleStatsFlush() {
        statsDirty.set(true)
        if (!isUiForeground && !BuildConfig.D14_DEVICE_TEST) return
        synchronized(flushLock) {
            if (statsFlushJob?.isActive == true) return
            statsFlushJob = flowFlushScope.launch {
                do {
                    delay(FOREGROUND_STATS_FLUSH_MS)
                    if (!isUiForeground && !BuildConfig.D14_DEVICE_TEST) return@launch
                    statsDirty.set(false)
                    flushStatsNow()
                } while (statsDirty.get())
                synchronized(flushLock) {
                    statsFlushJob = null
                    if (statsDirty.get()) scheduleStatsFlush()
                }
            }
        }
    }

    private fun flushLogsNow() {
        liveLogsFlow.value = synchronized(logList) { logList.toList() }
    }

    private fun flushStatsNow() {
        diagnosticsFlow.value = diagnosticMetrics.snapshot()
    }
}
