package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertEquals

class BackgroundDnsLogPolicyTest {
    @Test
    fun firstBackgroundPlaintextIsImmediateAndRapidTransportResolverChangesShareGlobalRate() {
        var now = 0L
        val policy = policy(now = { now }, intervalMillis = 10)

        assertEquals(
            BackgroundDnsLogPolicy.Decision.Detail,
            record(policy, DnsTransport.PLAINTEXT_UDP, 1)
        )
        var quietDecisions = 0
        repeat(500) { index ->
            assertEquals(
                BackgroundDnsLogPolicy.Decision.None,
                record(policy, DnsTransport.ENCRYPTED_HTTPS, if (index % 2 == 0) 1 else 2)
            )
            assertEquals(
                BackgroundDnsLogPolicy.Decision.None,
                record(
                    policy,
                    if (index % 2 == 0) DnsTransport.PLAINTEXT_TCP else DnsTransport.PLAINTEXT_UDP,
                    if (index % 2 == 0) 2 else 1
                )
            )
            quietDecisions += 2
        }
        assertEquals(BackgroundDnsLogPolicy.Decision.None, record(policy, DnsTransport.ENCRYPTED_HTTPS, 2))
        quietDecisions++
        assertEquals(1001, quietDecisions)

        now = 10_000_000L
        assertEquals(
            BackgroundDnsLogPolicy.Decision.Summary(
                BackgroundDnsLogSummary(
                    coalescedEventCount = 1001,
                    latestTransport = DnsTransport.ENCRYPTED_HTTPS,
                    latestResolverId = 2
                )
            ),
            record(policy, DnsTransport.ENCRYPTED_HTTPS, 2)
        )
    }

    @Test
    fun largeUdpTcpBurstIsRateLimitedToOneDetailAndOneSummaryDecision() {
        var now = 0L
        val policy = policy(now = { now }, intervalMillis = 10)

        assertEquals(
            BackgroundDnsLogPolicy.Decision.Detail,
            record(policy, DnsTransport.PLAINTEXT_UDP, 7)
        )
        var quietDecisions = 0
        repeat(10_000) { index ->
            assertEquals(
                BackgroundDnsLogPolicy.Decision.None,
                record(
                    policy,
                    if (index % 2 == 0) DnsTransport.PLAINTEXT_TCP else DnsTransport.PLAINTEXT_UDP,
                    7
                )
            )
            quietDecisions++
        }
        assertEquals(10_000, quietDecisions)

        now = 10_000_000L
        assertEquals(
            BackgroundDnsLogPolicy.Decision.Summary(
                BackgroundDnsLogSummary(
                    coalescedEventCount = 10_001,
                    latestTransport = DnsTransport.PLAINTEXT_TCP,
                    latestResolverId = 7
                )
            ),
            record(policy, DnsTransport.PLAINTEXT_TCP, 7)
        )
    }

    @Test
    fun doHRecoveryAndResolverSwitchAreSummarizedWithLatestActualContext() {
        var now = 0L
        val policy = policy(now = { now }, intervalMillis = 10)

        assertEquals(BackgroundDnsLogPolicy.Decision.Detail, record(policy, DnsTransport.PLAINTEXT_TCP, 1))
        assertEquals(BackgroundDnsLogPolicy.Decision.None, record(policy, DnsTransport.ENCRYPTED_HTTPS, 1))
        assertEquals(BackgroundDnsLogPolicy.Decision.None, record(policy, DnsTransport.ENCRYPTED_HTTPS, 2))

        now = 10_000_000L
        assertEquals(
            BackgroundDnsLogPolicy.Decision.Summary(
                BackgroundDnsLogSummary(
                    coalescedEventCount = 2,
                    latestTransport = DnsTransport.ENCRYPTED_HTTPS,
                    latestResolverId = 2
                )
            ),
            record(policy, DnsTransport.ENCRYPTED_HTTPS, 2)
        )
    }

    @Test
    fun foregroundDetailsDoNotResetTheWindowOrCountAsCoalescedBackgroundEvents() {
        var now = 0L
        val policy = policy(now = { now }, intervalMillis = 10)

        assertEquals(BackgroundDnsLogPolicy.Decision.Detail, record(policy, DnsTransport.PLAINTEXT_UDP, 1))
        assertEquals(BackgroundDnsLogPolicy.Decision.None, record(policy, DnsTransport.PLAINTEXT_TCP, 1))
        assertEquals(
            BackgroundDnsLogPolicy.Decision.Detail,
            record(policy, DnsTransport.ENCRYPTED_HTTPS, 2, isForeground = true)
        )
        assertEquals(
            BackgroundDnsLogPolicy.Decision.Detail,
            record(policy, DnsTransport.PLAINTEXT_TCP, 2, isForeground = true)
        )
        assertEquals(BackgroundDnsLogPolicy.Decision.None, record(policy, DnsTransport.PLAINTEXT_TCP, 2))

        now = 10_000_000L
        assertEquals(
            BackgroundDnsLogPolicy.Decision.Summary(
                BackgroundDnsLogSummary(
                    coalescedEventCount = 3,
                    latestTransport = DnsTransport.PLAINTEXT_TCP,
                    latestResolverId = 2
                )
            ),
            record(policy, DnsTransport.PLAINTEXT_TCP, 2)
        )
    }

    @Test
    fun doHOutcomesBeforeFirstBackgroundFallbackAreSilent() {
        val policy = policy(now = { 0L }, intervalMillis = 10)

        assertEquals(BackgroundDnsLogPolicy.Decision.None, record(policy, DnsTransport.ENCRYPTED_HTTPS, 1))
        assertEquals(BackgroundDnsLogPolicy.Decision.None, record(policy, DnsTransport.ENCRYPTED_HTTPS, 2))
        assertEquals(
            BackgroundDnsLogPolicy.Decision.Detail,
            record(policy, DnsTransport.PLAINTEXT_UDP, 2)
        )
    }

    @Test
    fun unavailableOutcomesAreIgnoredAndDueEventsReturnASummary() {
        var now = 0L
        val policy = policy(now = { now }, intervalMillis = 5)

        assertEquals(BackgroundDnsLogPolicy.Decision.Detail, record(policy, DnsTransport.PLAINTEXT_UDP, 1))
        assertEquals(BackgroundDnsLogPolicy.Decision.None, record(policy, DnsTransport.ENCRYPTED_HTTPS, 1))
        assertEquals(BackgroundDnsLogPolicy.Decision.None, record(policy, DnsTransport.ENCRYPTED_HTTPS, 1))
        assertEquals(BackgroundDnsLogPolicy.Decision.None, record(policy, DnsTransport.UNAVAILABLE, 1))

        now = 5_000_000L
        assertEquals(
            BackgroundDnsLogPolicy.Decision.Summary(
                BackgroundDnsLogSummary(
                    coalescedEventCount = 1,
                    latestTransport = DnsTransport.ENCRYPTED_HTTPS,
                    latestResolverId = 1
                )
            ),
            record(policy, DnsTransport.ENCRYPTED_HTTPS, 1)
        )
    }

    private fun record(
        policy: BackgroundDnsLogPolicy,
        transport: DnsTransport,
        resolverId: Int,
        isForeground: Boolean = false
    ): BackgroundDnsLogPolicy.Decision = policy.recordSuccessfulResolution(
        transport = transport,
        resolverId = resolverId,
        isForeground = isForeground
    )

    private fun policy(
        now: () -> Long,
        intervalMillis: Long
    ) = BackgroundDnsLogPolicy(
        intervalMillis = intervalMillis,
        nanoTime = now
    )
}
