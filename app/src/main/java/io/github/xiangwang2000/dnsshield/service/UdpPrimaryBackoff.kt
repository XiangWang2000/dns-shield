package io.github.xiangwang2000.dnsshield.service

/** Bounded primary-to-backup preference for one resolver/network generation. */
internal class UdpPrimaryBackoff(
    private val monotonicMillis: () -> Long = { System.nanoTime() / 1_000_000L },
    private val failureThreshold: Int = DEFAULT_FAILURE_THRESHOLD,
    private val cooldownMillis: Long = DEFAULT_COOLDOWN_MILLIS
) {
    internal class QueryPermit internal constructor(
        val preferBackup: Boolean,
        internal val probeId: Long?,
        internal val enabled: Boolean
    )

    private val lock = Any()
    private var consecutiveQualifiedFailures = 0
    private var preferBackupUntilMillis: Long? = null
    private var probeInFlight: Long? = null
    private var nextProbeId = 0L

    init {
        require(failureThreshold > 0)
        require(cooldownMillis > 0L)
    }

    fun beginQuery(
        primary: DnsUdpUpstreamEndpoint,
        secondary: DnsUdpUpstreamEndpoint
    ): QueryPermit {
        if (!areDistinct(primary, secondary)) return QueryPermit(false, null, false)

        synchronized(lock) {
            val cooldownEnd = preferBackupUntilMillis ?: return QueryPermit(false, null, true)
            if (monotonicMillis() < cooldownEnd || probeInFlight != null) {
                return QueryPermit(true, null, true)
            }

            val probeId = ++nextProbeId
            probeInFlight = probeId
            return QueryPermit(false, probeId, true)
        }
    }

    fun finishQuery(
        permit: QueryPermit,
        primaryAttempted: Boolean,
        primaryTimedOut: Boolean,
        primaryResponded: Boolean,
        primarySucceeded: Boolean,
        backupSucceeded: Boolean
    ) {
        if (!permit.enabled) return

        synchronized(lock) {
            if (permit.probeId != null && probeInFlight != permit.probeId) return

            if (primarySucceeded) {
                clearState()
                return
            }

            val qualifiedFailure = primaryTimedOut && backupSucceeded
            if (primaryAttempted && !qualifiedFailure) {
                consecutiveQualifiedFailures = 0
            }
            if (primaryResponded) consecutiveQualifiedFailures = 0

            if (qualifiedFailure) {
                if (permit.probeId != null || consecutiveQualifiedFailures + 1 >= failureThreshold) {
                    consecutiveQualifiedFailures = failureThreshold
                    preferBackupUntilMillis = addSaturated(monotonicMillis(), cooldownMillis)
                } else {
                    consecutiveQualifiedFailures++
                }
            }

            if (permit.probeId != null) probeInFlight = null
        }
    }

    fun abandonQuery(permit: QueryPermit) {
        if (!permit.enabled || permit.probeId == null) return
        synchronized(lock) {
            if (probeInFlight == permit.probeId) probeInFlight = null
        }
    }

    private fun clearState() {
        consecutiveQualifiedFailures = 0
        preferBackupUntilMillis = null
        probeInFlight = null
    }

    private fun areDistinct(
        primary: DnsUdpUpstreamEndpoint,
        secondary: DnsUdpUpstreamEndpoint
    ): Boolean = primary != secondary

    private fun addSaturated(value: Long, increment: Long): Long =
        if (value > Long.MAX_VALUE - increment) Long.MAX_VALUE else value + increment

    private companion object {
        const val DEFAULT_FAILURE_THRESHOLD = 2
        const val DEFAULT_COOLDOWN_MILLIS = 15_000L
    }
}
