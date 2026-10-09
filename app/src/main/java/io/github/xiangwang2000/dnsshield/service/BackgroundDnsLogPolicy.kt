package io.github.xiangwang2000.dnsshield.service

/** Latest successful outcome plus coalesced plaintext successes and transport/resolver transitions. */
internal data class BackgroundDnsLogSummary(
    val coalescedEventCount: Long,
    val latestTransport: DnsTransport,
    val latestResolverId: Int
)

/**
 * Bounds background transport logging globally across resolver and transport changes.
 *
 * The first background plaintext outcome is logged immediately. After that, each plaintext
 * success and each transport/resolver transition is coalesced under one monotonic interval.
 * Ordinary repeated DoH successes are quiet. Foreground details bypass and do not reset the
 * background window; all successful outcomes still update the latest observed transport/resolver.
 */
internal class BackgroundDnsLogPolicy(
    intervalMillis: Long = DEFAULT_INTERVAL_MILLIS,
    private val nanoTime: () -> Long = System::nanoTime,
    private val sink: (String) -> Unit
) {
    private val intervalNanos: Long
    private val stateLock = Any()
    private var lastBackgroundNoticeNanos: Long? = null
    private var coalescedBackgroundEventCount = 0L
    private var hasLatestOutcome = false
    private var latestTransport = DnsTransport.UNAVAILABLE
    private var latestResolverId = 0
    private var hasBackgroundPlaintextOutcome = false

    init {
        require(intervalMillis > 0L)
        require(intervalMillis <= Long.MAX_VALUE / NANOS_PER_MILLISECOND)
        intervalNanos = intervalMillis * NANOS_PER_MILLISECOND
    }

    /**
     * Records a successful DoH, UDP/53, or TCP/53 resolution. Unavailable outcomes are ignored.
     * Message builders and the sink are called only for foreground detail, the first background
     * plaintext outcome, or a due background summary.
     */
    fun logSuccessfulResolution(
        transport: DnsTransport,
        resolverId: Int,
        isForeground: Boolean,
        detailMessage: () -> String,
        summaryMessage: (BackgroundDnsLogSummary) -> String
    ) {
        if (transport == DnsTransport.UNAVAILABLE) return

        val decision = synchronized(stateLock) {
            val hadPreviousOutcome = hasLatestOutcome
            val previousTransport = latestTransport
            val previousResolverId = latestResolverId
            latestTransport = transport
            latestResolverId = resolverId
            hasLatestOutcome = true

            if (isForeground) {
                return@synchronized Decision.Detail
            }

            val isPlaintext = transport == DnsTransport.PLAINTEXT_UDP ||
                transport == DnsTransport.PLAINTEXT_TCP
            if (isPlaintext && !hasBackgroundPlaintextOutcome) {
                hasBackgroundPlaintextOutcome = true
                val now = nanoTime()
                lastBackgroundNoticeNanos = now
                return@synchronized Decision.Detail
            }

            // DoH traffic before the first background fallback needs no background notice.
            if (!hasBackgroundPlaintextOutcome) {
                return@synchronized Decision.None
            }

            val isRelevantEvent = isPlaintext ||
                !hadPreviousOutcome ||
                previousTransport != transport ||
                previousResolverId != resolverId
            if (isRelevantEvent) coalescedBackgroundEventCount++

            val pendingEvents = coalescedBackgroundEventCount
            if (pendingEvents == 0L) {
                Decision.None
            } else {
                val now = nanoTime()
                val lastNotice = lastBackgroundNoticeNanos
                if (lastNotice == null || now - lastNotice < intervalNanos) {
                    Decision.None
                } else {
                    lastBackgroundNoticeNanos = now
                    coalescedBackgroundEventCount = 0L
                    Decision.Summary(
                        BackgroundDnsLogSummary(
                            coalescedEventCount = pendingEvents,
                            latestTransport = transport,
                            latestResolverId = resolverId
                        )
                    )
                }
            }
        }

        when (decision) {
            Decision.Detail -> sink(detailMessage())
            is Decision.Summary -> sink(summaryMessage(decision.summary))
            Decision.None -> Unit
        }
    }

    private sealed interface Decision {
        data object Detail : Decision
        data class Summary(val summary: BackgroundDnsLogSummary) : Decision
        data object None : Decision
    }

    private companion object {
        const val DEFAULT_INTERVAL_MILLIS = 60_000L
        const val NANOS_PER_MILLISECOND = 1_000_000L
    }
}
