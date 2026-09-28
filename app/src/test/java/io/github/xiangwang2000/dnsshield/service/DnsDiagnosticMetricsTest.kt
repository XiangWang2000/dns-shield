package io.github.xiangwang2000.dnsshield.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsDiagnosticMetricsTest {
    @Test
    fun terminalResultsConserveReceivedQueriesAndClassificationsStaySeparate() {
        val metrics = DnsDiagnosticMetrics()
        val cacheHit = metrics.begin(0L)
        val coalesced = metrics.begin(0L)
        val overloaded = metrics.begin(0L)
        val blocked = metrics.begin(0L)
        val rejected = metrics.begin(0L)

        metrics.recordCacheHit(cacheHit)
        metrics.recordCoalesced(coalesced)
        metrics.recordOverload(overloaded)
        metrics.recordTransportAttempt(overloaded, DnsUpstreamTransport.DOH_CALL_QUEUED)
        metrics.recordTransportAttempt(overloaded, DnsUpstreamTransport.UDP)
        metrics.recordUdpRetryAttempt(overloaded)
        metrics.recordFallbackAttempt(overloaded)
        assertTrue(metrics.complete(cacheHit, DnsClientTerminalOutcome.RESOLVED, completedAtNanos = 1_000_000L))
        assertTrue(metrics.complete(coalesced, DnsClientTerminalOutcome.RESOLVED, completedAtNanos = 2_000_000L))
        assertTrue(metrics.complete(overloaded, DnsClientTerminalOutcome.FAILED, completedAtNanos = 3_000_000L))
        assertTrue(metrics.complete(blocked, DnsClientTerminalOutcome.BLOCKED, completedAtNanos = 4_000_000L, savedBytes = 500L))
        assertTrue(metrics.complete(rejected, DnsClientTerminalOutcome.REJECTED, completedAtNanos = 5_000_000L))

        assertFalse(metrics.complete(overloaded, DnsClientTerminalOutcome.RESOLVED, completedAtNanos = 6_000_000L))
        metrics.recordOverload(overloaded)
        val snapshot = metrics.snapshot()

        assertEquals(5L, snapshot.received)
        assertEquals(2L, snapshot.resolved)
        assertEquals(1L, snapshot.blocked)
        assertEquals(1L, snapshot.failed)
        assertEquals(1L, snapshot.rejected)
        assertEquals(snapshot.received, snapshot.terminalCount + snapshot.pending)
        assertEquals(1L, snapshot.cacheHits)
        assertEquals(1L, snapshot.coalesced)
        assertEquals(1L, snapshot.overloaded)
        assertEquals(1L, snapshot.dohCallsQueued)
        assertEquals(1L, snapshot.udpAttempts)
        assertEquals(1L, snapshot.udpRetryAttempts)
        assertEquals(0L, snapshot.tcpAttempts)
        assertEquals(1L, snapshot.fallbackAttempts)
        assertEquals(500L, snapshot.estimatedSavedBytes)
        assertEquals(0L, snapshot.pending)
        assertEquals(5, snapshot.latency.sampleCount)
    }

    @Test
    fun pendingDepthTracksOutstandingRequestsAndResetIgnoresOldCompletions() {
        val metrics = DnsDiagnosticMetrics()
        val outstanding = metrics.begin(0L)
        metrics.begin(0L)
        assertEquals(2L, metrics.snapshot().pending)
        assertEquals(2L, metrics.snapshot().peakPending)
        assertEquals(metrics.snapshot().received, metrics.snapshot().terminalCount + metrics.snapshot().pending)

        metrics.reset()
        assertFalse(metrics.complete(outstanding, DnsClientTerminalOutcome.FAILED, completedAtNanos = 10L))
        assertEquals(DnsDiagnosticsSnapshot(), metrics.snapshot())
    }

    @Test
    fun latencyStorageAndPercentilesStayWithinFixedWindow() {
        val metrics = DnsDiagnosticMetrics()
        val sampleCount = DnsDiagnosticMetrics.LATENCY_WINDOW_SIZE + 10

        repeat(sampleCount) { index ->
            val request = metrics.begin(0L)
            metrics.complete(
                request,
                DnsClientTerminalOutcome.RESOLVED,
                completedAtNanos = (index + 1L) * 1_000_000L
            )
        }

        val latency = metrics.snapshot().latency
        assertEquals(DnsDiagnosticMetrics.LATENCY_WINDOW_SIZE, latency.sampleCount)
        assertEquals(74L, latency.p50Millis)
        assertEquals(132L, latency.p95Millis)
        assertNull(DnsDiagnosticMetrics().snapshot().latency.p50Millis)
    }
}
