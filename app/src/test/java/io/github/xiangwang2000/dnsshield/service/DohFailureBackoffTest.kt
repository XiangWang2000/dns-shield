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
            assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
            backoff.recordFailure(ENDPOINT, GENERATION)
        }
        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
        backoff.recordFailure(ENDPOINT, GENERATION)
        assertFalse(backoff.tryAcquire(ENDPOINT, GENERATION))

        now = 10_000_000L
        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
        assertFalse(backoff.tryAcquire(ENDPOINT, GENERATION))

        backoff.recordSuccess(ENDPOINT, GENERATION)
        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
    }

    @Test
    fun failedRecoveryProbeReopensCooldown() {
        var now = 0L
        val backoff = DohFailureBackoff(
            failureThreshold = 1,
            cooldownMillis = 10,
            nanoTime = { now }
        )

        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
        backoff.recordFailure(ENDPOINT, GENERATION)
        now = 10_000_000L
        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
        backoff.recordFailure(ENDPOINT, GENERATION)

        now = 19_999_999L
        assertFalse(backoff.tryAcquire(ENDPOINT, GENERATION))
        now = 20_000_000L
        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
    }

    @Test
    fun successResetsConsecutiveFailures() {
        val backoff = DohFailureBackoff(failureThreshold = 2, cooldownMillis = 10)

        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
        backoff.recordFailure(ENDPOINT, GENERATION)
        backoff.recordSuccess(ENDPOINT, GENERATION)

        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
        backoff.recordFailure(ENDPOINT, GENERATION)
        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
    }

    @Test
    fun cancelledProbeCanBeRetried() {
        var now = 0L
        val backoff = DohFailureBackoff(
            failureThreshold = 1,
            cooldownMillis = 10,
            nanoTime = { now }
        )

        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
        backoff.recordFailure(ENDPOINT, GENERATION)
        now = 10_000_000L
        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
        backoff.cancelAttempt(ENDPOINT, GENERATION)
        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
    }

    @Test
    fun endpointsAreTrackedIndependently() {
        val backoff = DohFailureBackoff(failureThreshold = 1, cooldownMillis = 10)

        assertTrue(backoff.tryAcquire(ENDPOINT, GENERATION))
        backoff.recordFailure(ENDPOINT, GENERATION)

        assertFalse(backoff.tryAcquire(ENDPOINT, GENERATION))
        assertTrue(backoff.tryAcquire(OTHER_ENDPOINT, GENERATION))
    }

    @Test
    fun sameUrlWithDifferentBootstrapDoesNotShareBackoff() {
        val backoff = DohFailureBackoff(failureThreshold = 1, cooldownMillis = 10)
        val first = ENDPOINT
        val second = first.copy(bootstrapAddresses = listOf("192.0.2.2"))

        assertTrue(backoff.tryAcquire(first, GENERATION))
        backoff.recordFailure(first, GENERATION)

        assertFalse(backoff.tryAcquire(first, GENERATION))
        assertTrue(
            backoff.tryAcquire(second, GENERATION),
            "same URL with a different bootstrap must remain available"
        )
    }

    @Test
    fun newNetworkGenerationResetsBackoffAndIgnoresLateFailuresFromOldNetwork() {
        val backoff = DohFailureBackoff(failureThreshold = 1, cooldownMillis = 10)

        val oldGeneration = DohFailureBackoff.Generation(resolverGeneration = 0, networkGeneration = 0)
        val newGeneration = DohFailureBackoff.Generation(resolverGeneration = 0, networkGeneration = 1)

        assertTrue(backoff.tryAcquire(ENDPOINT, oldGeneration))
        backoff.recordFailure(ENDPOINT, oldGeneration)
        assertFalse(backoff.tryAcquire(ENDPOINT, oldGeneration))

        backoff.resetForGeneration(newGeneration)
        backoff.recordFailure(ENDPOINT, oldGeneration)

        assertTrue(backoff.tryAcquire(ENDPOINT, newGeneration))
    }

    @Test
    fun lateResolverGenerationCompletionsCannotChangeNewBackoffState() {
        var now = 0L
        val backoff = DohFailureBackoff(
            failureThreshold = 2,
            cooldownMillis = 10,
            nanoTime = { now }
        )
        val oldGeneration = DohFailureBackoff.Generation(resolverGeneration = 0, networkGeneration = 0)
        val newGeneration = DohFailureBackoff.Generation(resolverGeneration = 1, networkGeneration = 0)

        assertTrue(backoff.tryAcquire(ENDPOINT, oldGeneration))
        backoff.resetForGeneration(newGeneration)
        repeat(2) {
            assertTrue(backoff.tryAcquire(ENDPOINT, newGeneration))
            backoff.recordFailure(ENDPOINT, newGeneration)
        }
        assertFalse(backoff.tryAcquire(ENDPOINT, newGeneration))

        now = 10_000_000L
        assertTrue(backoff.tryAcquire(ENDPOINT, newGeneration))
        backoff.cancelAttempt(ENDPOINT, oldGeneration)
        backoff.recordSuccess(ENDPOINT, oldGeneration)
        backoff.recordFailure(ENDPOINT, oldGeneration)
        assertFalse(backoff.tryAcquire(ENDPOINT, newGeneration))

        backoff.recordFailure(ENDPOINT, newGeneration)
        assertFalse(backoff.tryAcquire(ENDPOINT, newGeneration))
    }

    private companion object {
        val GENERATION = DohFailureBackoff.Generation(resolverGeneration = 0, networkGeneration = 0)
        val ENDPOINT = DnsDohEndpoint(
            "https://dns.google/dns-query",
            "dns.google",
            listOf("8.8.8.8", "8.8.4.4"),
            isCustom = false
        )
        val OTHER_ENDPOINT = DnsDohEndpoint(
            "https://cloudflare-dns.com/dns-query",
            "cloudflare-dns.com",
            listOf("1.1.1.1", "1.0.0.1"),
            isCustom = false
        )
    }
}
