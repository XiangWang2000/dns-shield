package io.github.xiangwang2000.dnsshield.service

internal enum class DnsClientTerminalOutcome {
    RESOLVED,
    BLOCKED,
    FAILED,
    REJECTED
}

internal enum class DnsUpstreamTransport {
    // OkHttp accepted the call into its queue; this does not confirm a network write.
    DOH_CALL_QUEUED,
    UDP,
    TCP
}

data class DnsLatencySummary(
    val sampleCount: Int = 0,
    val p50Millis: Long? = null,
    val p95Millis: Long? = null
)

data class DnsCoalescedWaitSummary(
    val sampleCount: Int = 0,
    val p50Millis: Long? = null,
    val p95Millis: Long? = null,
    val p99Millis: Long? = null
)

data class DnsDiagnosticsSnapshot(
    val received: Long = 0,
    val resolved: Long = 0,
    val blocked: Long = 0,
    val failed: Long = 0,
    val rejected: Long = 0,
    val cacheHits: Long = 0,
    val coalesced: Long = 0,
    val overloaded: Long = 0,
    val dohCallsQueued: Long = 0,
    val udpAttempts: Long = 0,
    val udpRetryAttempts: Long = 0,
    val tcpAttempts: Long = 0,
    val fallbackAttempts: Long = 0,
    val pending: Long = 0,
    val peakPending: Long = 0,
    val estimatedSavedBytes: Long = 0,
    val latency: DnsLatencySummary = DnsLatencySummary(),
    val coalescedWait: DnsCoalescedWaitSummary = DnsCoalescedWaitSummary()
) {
    val terminalCount: Long get() = resolved + blocked + failed + rejected
}

/** Thread-safe cumulative counters and a fixed-size rolling latency sample. */
internal class DnsDiagnosticMetrics(
    private val latencyWindowSize: Int = LATENCY_WINDOW_SIZE
) {
    internal class Request internal constructor(
        internal val generation: Long,
        internal val receivedAtNanos: Long
    ) {
        internal var completed = false
    }

    private val lock = Any()
    private val latencySamplesNanos = LongArray(latencyWindowSize)
    private val queueWaitSamplesNanos = LongArray(latencyWindowSize)
    private var latencySampleCount = 0
    private var nextLatencySample = 0
    private var queueWaitSampleCount = 0
    private var nextQueueWaitSample = 0
    private var generation = 0L

    private var received = 0L
    private var resolved = 0L
    private var blocked = 0L
    private var failed = 0L
    private var rejected = 0L
    private var cacheHits = 0L
    private var coalesced = 0L
    private var overloaded = 0L
    private var dohCallsQueued = 0L
    private var udpAttempts = 0L
    private var udpRetryAttempts = 0L
    private var tcpAttempts = 0L
    private var fallbackAttempts = 0L
    private var pending = 0L
    private var peakPending = 0L
    private var estimatedSavedBytes = 0L

    init {
        require(latencyWindowSize > 0)
    }

    fun begin(receivedAtNanos: Long): Request = synchronized(lock) {
        received++
        pending++
        peakPending = maxOf(peakPending, pending)
        Request(generation, receivedAtNanos)
    }

    fun recordCacheHit(request: Request) = updateActive(request) { cacheHits++ }

    fun recordCoalesced(request: Request) = updateActive(request) { coalesced++ }

    /** Overload is a classification of a failed client query, not another terminal result. */
    fun recordOverload(request: Request) = updateActive(request) { overloaded++ }

    fun recordTransportAttempt(request: Request, transport: DnsUpstreamTransport) = updateActive(request) {
        when (transport) {
            DnsUpstreamTransport.DOH_CALL_QUEUED -> dohCallsQueued++
            DnsUpstreamTransport.UDP -> udpAttempts++
            DnsUpstreamTransport.TCP -> tcpAttempts++
        }
    }

    fun recordFallbackAttempt(request: Request) = updateActive(request) { fallbackAttempts++ }

    fun recordUdpRetryAttempt(request: Request) = updateActive(request) { udpRetryAttempts++ }

    fun recordCoalescedWait(request: Request, elapsedNanos: Long) = updateActive(request) {
        queueWaitSamplesNanos[nextQueueWaitSample] = elapsedNanos.coerceAtLeast(0L)
        nextQueueWaitSample = (nextQueueWaitSample + 1) % latencyWindowSize
        queueWaitSampleCount = minOf(queueWaitSampleCount + 1, latencyWindowSize)
    }

    fun complete(
        request: Request,
        outcome: DnsClientTerminalOutcome,
        completedAtNanos: Long = System.nanoTime(),
        savedBytes: Long = 0L
    ): Boolean = synchronized(lock) {
        if (request.completed || request.generation != generation) {
            request.completed = true
            return@synchronized false
        }

        request.completed = true
        when (outcome) {
            DnsClientTerminalOutcome.RESOLVED -> resolved++
            DnsClientTerminalOutcome.BLOCKED -> {
                blocked++
                estimatedSavedBytes += savedBytes.coerceAtLeast(0L)
            }
            DnsClientTerminalOutcome.FAILED -> failed++
            DnsClientTerminalOutcome.REJECTED -> rejected++
        }
        pending--
        check(pending >= 0L)
        recordLatency((completedAtNanos - request.receivedAtNanos).coerceAtLeast(0L))
        true
    }

    fun snapshot(): DnsDiagnosticsSnapshot = synchronized(lock) {
        val sortedSamples = latencySamplesNanos.copyOf(latencySampleCount).sortedArray()
        val sortedQueueWaitSamples = queueWaitSamplesNanos.copyOf(queueWaitSampleCount).sortedArray()
        DnsDiagnosticsSnapshot(
            received = received,
            resolved = resolved,
            blocked = blocked,
            failed = failed,
            rejected = rejected,
            cacheHits = cacheHits,
            coalesced = coalesced,
            overloaded = overloaded,
            dohCallsQueued = dohCallsQueued,
            udpAttempts = udpAttempts,
            udpRetryAttempts = udpRetryAttempts,
            tcpAttempts = tcpAttempts,
            fallbackAttempts = fallbackAttempts,
            pending = pending,
            peakPending = peakPending,
            estimatedSavedBytes = estimatedSavedBytes,
            latency = DnsLatencySummary(
                sampleCount = latencySampleCount,
                p50Millis = percentileMillis(sortedSamples, 50),
                p95Millis = percentileMillis(sortedSamples, 95)
            ),
            coalescedWait = DnsCoalescedWaitSummary(
                sampleCount = queueWaitSampleCount,
                p50Millis = percentileMillis(sortedQueueWaitSamples, 50),
                p95Millis = percentileMillis(sortedQueueWaitSamples, 95),
                p99Millis = percentileMillis(sortedQueueWaitSamples, 99)
            )
        )
    }

    /** Reset displayed session totals; completions from requests begun before reset are ignored. */
    fun reset() = synchronized(lock) {
        generation++
        received = 0L
        resolved = 0L
        blocked = 0L
        failed = 0L
        rejected = 0L
        cacheHits = 0L
        coalesced = 0L
        overloaded = 0L
        dohCallsQueued = 0L
        udpAttempts = 0L
        udpRetryAttempts = 0L
        tcpAttempts = 0L
        fallbackAttempts = 0L
        pending = 0L
        peakPending = 0L
        estimatedSavedBytes = 0L
        latencySampleCount = 0
        nextLatencySample = 0
        queueWaitSampleCount = 0
        nextQueueWaitSample = 0
    }

    private fun updateActive(request: Request, update: () -> Unit) = synchronized(lock) {
        if (request.generation == generation && !request.completed) update()
    }

    private fun recordLatency(elapsedNanos: Long) {
        latencySamplesNanos[nextLatencySample] = elapsedNanos
        nextLatencySample = (nextLatencySample + 1) % latencyWindowSize
        latencySampleCount = minOf(latencySampleCount + 1, latencyWindowSize)
    }

    private fun percentileMillis(sortedSamples: LongArray, percentile: Int): Long? {
        if (sortedSamples.isEmpty()) return null
        val rank = (sortedSamples.size * percentile + 99) / 100
        return sortedSamples[(rank - 1).coerceAtLeast(0)] / NANOS_PER_MILLISECOND
    }

    companion object {
        const val LATENCY_WINDOW_SIZE = 128
        private const val NANOS_PER_MILLISECOND = 1_000_000L
    }
}
