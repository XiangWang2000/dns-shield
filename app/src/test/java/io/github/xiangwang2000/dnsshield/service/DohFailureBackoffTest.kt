package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DohFailureBackoffTest {
    @Test
    fun opensAfterThresholdAndAllowsOneRecoveryProbe() {
        var now = 0L
        val backoff = DohFailureBackoff(
            failureThreshold = 3,
            cooldownMillis = 10,
            nanoTime = { now }
        )

        repeat(2) {
            assertTrue(backoff.tryAcquire(ENDPOINT))
            backoff.recordFailure(ENDPOINT)
        }
        assertTrue(backoff.tryAcquire(ENDPOINT))
        backoff.recordFailure(ENDPOINT)
        assertFalse(backoff.tryAcquire(ENDPOINT))

        now = 10_000_000L
        assertTrue(backoff.tryAcquire(ENDPOINT))
        assertFalse(backoff.tryAcquire(ENDPOINT))

        backoff.recordSuccess(ENDPOINT)
        assertTrue(backoff.tryAcquire(ENDPOINT))
    }

    @Test
    fun failedRecoveryProbeReopensCooldown() {
        var now = 0L
        val backoff = DohFailureBackoff(
            failureThreshold = 1,
            cooldownMillis = 10,
            nanoTime = { now }
        )

        assertTrue(backoff.tryAcquire(ENDPOINT))
        backoff.recordFailure(ENDPOINT)
        now = 10_000_000L
        assertTrue(backoff.tryAcquire(ENDPOINT))
        backoff.recordFailure(ENDPOINT)

        now = 19_999_999L
        assertFalse(backoff.tryAcquire(ENDPOINT))
        now = 20_000_000L
        assertTrue(backoff.tryAcquire(ENDPOINT))
    }

    @Test
    fun successResetsConsecutiveFailures() {
        val backoff = DohFailureBackoff(failureThreshold = 2, cooldownMillis = 10)

        assertTrue(backoff.tryAcquire(ENDPOINT))
        backoff.recordFailure(ENDPOINT)
        backoff.recordSuccess(ENDPOINT)

        assertTrue(backoff.tryAcquire(ENDPOINT))
        backoff.recordFailure(ENDPOINT)
        assertTrue(backoff.tryAcquire(ENDPOINT))
    }

    @Test
    fun cancelledProbeCanBeRetried() {
        var now = 0L
        val backoff = DohFailureBackoff(
            failureThreshold = 1,
            cooldownMillis = 10,
            nanoTime = { now }
        )

        assertTrue(backoff.tryAcquire(ENDPOINT))
        backoff.recordFailure(ENDPOINT)
        now = 10_000_000L
        assertTrue(backoff.tryAcquire(ENDPOINT))
        backoff.cancelAttempt(ENDPOINT)
        assertTrue(backoff.tryAcquire(ENDPOINT))
    }

    @Test
    fun endpointsAreTrackedIndependently() {
        val backoff = DohFailureBackoff(failureThreshold = 1, cooldownMillis = 10)

        assertTrue(backoff.tryAcquire(ENDPOINT))
        backoff.recordFailure(ENDPOINT)

        assertFalse(backoff.tryAcquire(ENDPOINT))
        assertTrue(backoff.tryAcquire(OTHER_ENDPOINT))
    }

    private companion object {
        const val ENDPOINT = "https://dns.google/dns-query"
        const val OTHER_ENDPOINT = "https://cloudflare-dns.com/dns-query"
    }
}
