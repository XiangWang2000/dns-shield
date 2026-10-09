package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertEquals

class BackgroundDnsLogPolicyTest {
    @Test
    fun firstBackgroundPlaintextIsImmediateAndRapidTransportResolverChangesShareGlobalRate() {
        var now = 0L
        val messages = mutableListOf<String>()
        val policy = policy(now = { now }, messages = messages, intervalMillis = 10)

        record(policy, DnsTransport.PLAINTEXT_UDP, 1)
        repeat(500) { index ->
            record(policy, DnsTransport.ENCRYPTED_HTTPS, if (index % 2 == 0) 1 else 2)
            record(
                policy,
                if (index % 2 == 0) DnsTransport.PLAINTEXT_TCP else DnsTransport.PLAINTEXT_UDP,
                if (index % 2 == 0) 2 else 1
            )
        }
        record(policy, DnsTransport.ENCRYPTED_HTTPS, 2)

        assertEquals(listOf("detail:1:PLAINTEXT_UDP"), messages)

        now = 10_000_000L
        record(policy, DnsTransport.ENCRYPTED_HTTPS, 2)

        assertEquals(
            listOf(
                "detail:1:PLAINTEXT_UDP",
                "summary:1001:ENCRYPTED_HTTPS:2"
            ),
            messages
        )
    }

    @Test
    fun largeUdpTcpBurstIsRateLimitedWithoutRepeatedFormatting() {
        var now = 0L
        val messages = mutableListOf<String>()
        var detailsFormatted = 0
        var summariesFormatted = 0
        val policy = BackgroundDnsLogPolicy(
            intervalMillis = 10,
            nanoTime = { now },
            sink = messages::add
        )
        fun record(transport: DnsTransport) {
            policy.logSuccessfulResolution(
                transport = transport,
                resolverId = 7,
                isForeground = false,
                detailMessage = { detailsFormatted++; "detail" },
                summaryMessage = {
                    summariesFormatted++
                    "summary:${it.coalescedEventCount}:${it.latestTransport}:${it.latestResolverId}"
                }
            )
        }

        record(DnsTransport.PLAINTEXT_UDP)
        repeat(10_000) { index ->
            record(if (index % 2 == 0) DnsTransport.PLAINTEXT_TCP else DnsTransport.PLAINTEXT_UDP)
        }

        assertEquals(1, detailsFormatted)
        assertEquals(0, summariesFormatted)
        assertEquals(listOf("detail"), messages)

        now = 10_000_000L
        record(DnsTransport.PLAINTEXT_TCP)

        assertEquals(1, detailsFormatted)
        assertEquals(1, summariesFormatted)
        assertEquals(listOf("detail", "summary:10001:PLAINTEXT_TCP:7"), messages)
    }

    @Test
    fun doHRecoveryAndResolverSwitchAreSummarizedWithLatestActualContext() {
        var now = 0L
        val messages = mutableListOf<String>()
        val policy = policy(now = { now }, messages = messages, intervalMillis = 10)

        record(policy, DnsTransport.PLAINTEXT_TCP, 1)
        record(policy, DnsTransport.ENCRYPTED_HTTPS, 1)
        record(policy, DnsTransport.ENCRYPTED_HTTPS, 2)
        assertEquals(listOf("detail:1:PLAINTEXT_TCP"), messages)

        now = 10_000_000L
        record(policy, DnsTransport.ENCRYPTED_HTTPS, 2)

        assertEquals(
            listOf(
                "detail:1:PLAINTEXT_TCP",
                "summary:2:ENCRYPTED_HTTPS:2"
            ),
            messages
        )
    }

    @Test
    fun foregroundDetailsDoNotResetTheWindowOrCountAsCoalescedBackgroundEvents() {
        var now = 0L
        val messages = mutableListOf<String>()
        val policy = policy(now = { now }, messages = messages, intervalMillis = 10)

        record(policy, DnsTransport.PLAINTEXT_UDP, 1)
        record(policy, DnsTransport.PLAINTEXT_TCP, 1)
        record(policy, DnsTransport.ENCRYPTED_HTTPS, 2, isForeground = true)
        record(policy, DnsTransport.PLAINTEXT_TCP, 2, isForeground = true)
        record(policy, DnsTransport.PLAINTEXT_TCP, 2)

        assertEquals(
            listOf(
                "detail:1:PLAINTEXT_UDP",
                "detail:2:ENCRYPTED_HTTPS",
                "detail:2:PLAINTEXT_TCP"
            ),
            messages
        )

        now = 10_000_000L
        record(policy, DnsTransport.PLAINTEXT_TCP, 2)

        assertEquals(
            listOf(
                "detail:1:PLAINTEXT_UDP",
                "detail:2:ENCRYPTED_HTTPS",
                "detail:2:PLAINTEXT_TCP",
                "summary:3:PLAINTEXT_TCP:2"
            ),
            messages
        )
    }

    @Test
    fun doHOutcomesBeforeFirstBackgroundFallbackAreSilent() {
        val messages = mutableListOf<String>()
        val policy = policy(now = { 0L }, messages = messages, intervalMillis = 10)

        record(policy, DnsTransport.ENCRYPTED_HTTPS, 1)
        record(policy, DnsTransport.ENCRYPTED_HTTPS, 2)
        assertEquals(emptyList<String>(), messages)

        record(policy, DnsTransport.PLAINTEXT_UDP, 2)
        assertEquals(listOf("detail:2:PLAINTEXT_UDP"), messages)
    }

    @Test
    fun suppressedEventsDoNotFormatMessagesOrCallSink() {
        var now = 0L
        val messages = mutableListOf<String>()
        var detailsFormatted = 0
        var summariesFormatted = 0
        val policy = BackgroundDnsLogPolicy(
            intervalMillis = 5,
            nanoTime = { now },
            sink = messages::add
        )
        fun record(transport: DnsTransport, resolverId: Int, isForeground: Boolean = false) {
            policy.logSuccessfulResolution(
                transport = transport,
                resolverId = resolverId,
                isForeground = isForeground,
                detailMessage = { detailsFormatted++; "detail" },
                summaryMessage = {
                    summariesFormatted++
                    "summary:${it.coalescedEventCount}:${it.latestTransport}:${it.latestResolverId}"
                }
            )
        }

        record(DnsTransport.PLAINTEXT_UDP, 1)
        record(DnsTransport.ENCRYPTED_HTTPS, 1)
        record(DnsTransport.ENCRYPTED_HTTPS, 1)
        record(DnsTransport.UNAVAILABLE, 1)
        assertEquals(1, detailsFormatted)
        assertEquals(0, summariesFormatted)
        assertEquals(listOf("detail"), messages)

        now = 5_000_000L
        record(DnsTransport.ENCRYPTED_HTTPS, 1)
        assertEquals(1, detailsFormatted)
        assertEquals(1, summariesFormatted)
        assertEquals(listOf("detail", "summary:1:ENCRYPTED_HTTPS:1"), messages)
    }

    private fun record(
        policy: BackgroundDnsLogPolicy,
        transport: DnsTransport,
        resolverId: Int,
        isForeground: Boolean = false
    ) {
        policy.logSuccessfulResolution(
            transport = transport,
            resolverId = resolverId,
            isForeground = isForeground,
            detailMessage = { "detail:$resolverId:$transport" },
            summaryMessage = {
                "summary:${it.coalescedEventCount}:${it.latestTransport}:${it.latestResolverId}"
            }
        )
    }

    private fun policy(
        now: () -> Long,
        messages: MutableList<String>,
        intervalMillis: Long
    ) = BackgroundDnsLogPolicy(
        intervalMillis = intervalMillis,
        nanoTime = now,
        sink = messages::add
    )
}
