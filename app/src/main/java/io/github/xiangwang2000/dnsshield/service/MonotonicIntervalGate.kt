package io.github.xiangwang2000.dnsshield.service

/** Allows at most one event per interval using a monotonic clock. */
internal class MonotonicIntervalGate(
    intervalMillis: Long,
    private val nanoTime: () -> Long = System::nanoTime
) {
    private val intervalNanos = intervalMillis * NANOS_PER_MILLISECOND
    private val lock = Any()
    private var lastAllowedNanos: Long? = null

    init {
        require(intervalMillis > 0)
    }

    fun tryAcquire(): Boolean = synchronized(lock) {
        val now = nanoTime()
        val lastAllowed = lastAllowedNanos
        if (lastAllowed != null && now - lastAllowed < intervalNanos) {
            return false
        }

        lastAllowedNanos = now
        true
    }

    private companion object {
        const val NANOS_PER_MILLISECOND = 1_000_000L
    }
}
