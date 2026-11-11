package io.github.xiangwang2000.dnsshield.service

import java.net.InetAddress
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UdpPrimaryBackoffTest {
    @Test
    fun qualifiesAfterTwoUsableFallbacksAndAllowsOnePostCooldownProbe() {
        var nowMillis = 1_000L
        val backoff = UdpPrimaryBackoff(monotonicMillis = { nowMillis })
        val address = InetAddress.getByName("127.0.0.1")
        val primary = DnsUdpUpstreamEndpoint(address, 5301)
        val secondary = DnsUdpUpstreamEndpoint(address, 5302)

        val first = backoff.beginQuery(primary, secondary)
        assertFalse(first.preferBackup)
        backoff.finishQuery(
            permit = first,
            primaryAttempted = true,
            primaryTimedOut = true,
            primaryResponded = false,
            primarySucceeded = false,
            backupSucceeded = true
        )

        val unqualified = backoff.beginQuery(primary, secondary)
        backoff.finishQuery(
            permit = unqualified,
            primaryAttempted = true,
            primaryTimedOut = true,
            primaryResponded = false,
            primarySucceeded = false,
            backupSucceeded = false
        )

        val afterOneUsableFallback = backoff.beginQuery(primary, secondary)
        assertFalse(afterOneUsableFallback.preferBackup)
        backoff.finishQuery(
            permit = afterOneUsableFallback,
            primaryAttempted = true,
            primaryTimedOut = true,
            primaryResponded = false,
            primarySucceeded = false,
            backupSucceeded = true
        )

        val second = backoff.beginQuery(primary, secondary)
        assertFalse(second.preferBackup)
        backoff.finishQuery(
            permit = second,
            primaryAttempted = true,
            primaryTimedOut = true,
            primaryResponded = false,
            primarySucceeded = false,
            backupSucceeded = true
        )
        val cooldownQuery = backoff.beginQuery(primary, secondary)
        assertTrue(cooldownQuery.preferBackup)
        backoff.finishQuery(
            permit = cooldownQuery,
            primaryAttempted = false,
            primaryTimedOut = false,
            primaryResponded = false,
            primarySucceeded = false,
            backupSucceeded = true
        )

        nowMillis += 15_000L
        val probe = backoff.beginQuery(primary, secondary)
        assertFalse(probe.preferBackup)
        val concurrentQuery = backoff.beginQuery(primary, secondary)
        assertTrue(concurrentQuery.preferBackup)
        backoff.finishQuery(
            permit = concurrentQuery,
            primaryAttempted = false,
            primaryTimedOut = false,
            primaryResponded = false,
            primarySucceeded = false,
            backupSucceeded = true
        )
        backoff.finishQuery(
            permit = probe,
            primaryAttempted = true,
            primaryTimedOut = true,
            primaryResponded = false,
            primarySucceeded = false,
            backupSucceeded = true
        )
        assertTrue(backoff.beginQuery(primary, secondary).preferBackup)

        nowMillis += 15_000L
        val recoveryProbe = backoff.beginQuery(primary, secondary)
        assertFalse(recoveryProbe.preferBackup)
        backoff.finishQuery(
            permit = recoveryProbe,
            primaryAttempted = true,
            primaryTimedOut = false,
            primaryResponded = true,
            primarySucceeded = true,
            backupSucceeded = false
        )
        assertFalse(backoff.beginQuery(primary, secondary).preferBackup)
    }

    @Test
    fun identicalConfiguredEndpointsDisableAdaptiveOrdering() {
        val backoff = UdpPrimaryBackoff()
        val endpoint = DnsUdpUpstreamEndpoint(InetAddress.getByName("127.0.0.1"), 5301)

        val permit = backoff.beginQuery(endpoint, endpoint)

        assertFalse(permit.enabled)
        assertFalse(permit.preferBackup)
    }
}
