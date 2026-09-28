package io.github.xiangwang2000.dnsshield.service

import java.util.concurrent.TimeUnit

internal class DnsRequestDeadline private constructor(
    internal val deadlineNanos: Long
) {
    fun remainingMillis(nowNanos: Long = System.nanoTime()): Long {
        val remainingNanos = deadlineNanos - nowNanos
        if (remainingNanos <= 0L) return 0L
        return (remainingNanos + NANOS_PER_MILLI - 1L) / NANOS_PER_MILLI
    }

    fun remainingNanos(nowNanos: Long = System.nanoTime()): Long =
        (deadlineNanos - nowNanos).coerceAtLeast(0L)

    companion object {
        const val DEFAULT_TIMEOUT_MILLIS = 6_000L
        private const val NANOS_PER_MILLI = 1_000_000L

        fun fromReceivedAt(
            receivedAtNanos: Long,
            timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS
        ): DnsRequestDeadline {
            require(timeoutMillis > 0L)
            return DnsRequestDeadline(
                receivedAtNanos + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
            )
        }
    }
}
