package io.github.xiangwang2000.dnsshield.service

import android.content.Intent
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Verifies bounded unique-query admission and stop with pending DNS work through a real TUN. */
@RunWith(AndroidJUnit4::class)
class D14DnsAdmissionTest {
    @Test
    fun rejectsUniqueOverflowAndStopsWithPendingQueries() = runBlocking {
        assertTrue("Run only the isolated .d14test target.", BuildConfig.D14_DEVICE_TEST)
        val context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        assertEquals("io.github.xiangwang2000.dnsshield.d14test", context.packageName)
        ensureD14VpnConsent(context)
        assertEquals(
            "Stop an existing D14 VPN before running this isolated lifecycle test.",
            VpnLifecycleState.STOPPED,
            DnsVpnService.lifecycleStateFlow.value
        )

        val fixture = D14FakeUpstreamFixture(context)
        val upstream = fixture.upstream
        var heldClient: DatagramSocket? = null
        var serviceStartRequested = false
        var testFailure: Throwable? = null

        try {
            fixture.install()

            serviceStartRequested = true
            ContextCompat.startForegroundService(
                context,
                Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
            )
            d14WaitForLifecycle(VpnLifecycleState.RUNNING, 20_000L)
            val runId = System.nanoTime().toString(36)
            d14AssertDnsAnswer(d14AwaitRcode("d14-admission-ready-$runId.example.invalid", 0))
            val readyDeadline = SystemClock.elapsedRealtime() + 2_000L
            while (DnsVpnService.d14DiagnosticsSnapshot().pending > 0 && SystemClock.elapsedRealtime() < readyDeadline) {
                SystemClock.sleep(10L)
            }
            assertEquals("The readiness probe must finish before filling the slots.", 0L, DnsVpnService.d14DiagnosticsSnapshot().pending)
            DnsVpnService.resetD14Diagnostics()
            val diagnosticsBefore = DnsVpnService.d14DiagnosticsSnapshot()

            val busyDomains = (0 until MAX_UNIQUE_QUERIES).map {
                "d14-admission-$runId-$it.example.invalid"
            }
            upstream.droppedDomains.addAll(busyDomains)
            val tunDnsAddress = InetAddress.getByName(DnsVpnService.DUMMY_DNS_IP)
            val client = DatagramSocket().also { heldClient = it }
            val fillDeadline = SystemClock.elapsedRealtime() + 3_000L
            // Pace against real upstream receipts so TUN ingress cannot drop a startup burst.
            for ((index, domain) in busyDomains.withIndex()) {
                val remaining = fillDeadline - SystemClock.elapsedRealtime()
                if (remaining <= 0) break
                val query = d14BuildQuery(domain, 0x6200 + index)
                client.send(DatagramPacket(query, query.size, tunDnsAddress, 53))
                if (!upstream.waitForCount(domain, 1, remaining)) break
            }
            val saturated = DnsVpnService.d14DiagnosticsSnapshot()
            assertEquals(
                "Held queries did not reach the fake upstream: TUN received=${saturated.received}, " +
                    "UDP attempts=${saturated.udpAttempts}, pending=${saturated.pending}, " +
                    "failed=${saturated.failed}, overloaded=${saturated.overloaded}, fake failure=${upstream.failure}",
                MAX_UNIQUE_QUERIES,
                busyDomains.count { upstream.count(it) > 0 }
            )
            assertEquals(
                "All 24 admitted queries must still be pending before the overflow probe.",
                MAX_UNIQUE_QUERIES.toLong(),
                saturated.pending
            )
            assertEquals(diagnosticsBefore.overloaded, saturated.overloaded)

            val overflowDomain = "d14-admission-overflow-$runId.example.invalid"
            val response = d14SendQuery(overflowDomain, 0x6300, timeoutMillis = 1_500)
            assertEquals("A query beyond the 24-key cap must receive SERVFAIL.", 2, d14ResponseCode(response))
            val afterOverflow = DnsVpnService.d14DiagnosticsSnapshot()
            assertEquals(saturated.overloaded + 1, afterOverflow.overloaded)
            // The overflow probe may still be completing its response.
            assertTrue("A held upstream query must still be pending before stop.", afterOverflow.pending > 1)

            val stopStartedAt = SystemClock.elapsedRealtime()
            context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
            d14WaitForLifecycle(VpnLifecycleState.STOPPED, 5_000L)
            assertTrue(
                "Stopping with pending upstream work exceeded 2.5 seconds.",
                SystemClock.elapsedRealtime() - stopStartedAt < 2_500L
            )
            assertEquals("STOPPED must leave no pending queries.", 0L, DnsVpnService.d14DiagnosticsSnapshot().pending)
            serviceStartRequested = false

            // Once DNS workers have stopped, let the fake receiver drain queued datagrams.
            val markerDomain = "d14-admission-drain-$runId.example.invalid"
            upstream.droppedDomains.add(markerDomain)
            val marker = d14BuildQuery(markerDomain, 0x6301)
            DatagramSocket().use { socket ->
                socket.send(DatagramPacket(marker, marker.size, InetAddress.getByName("127.0.0.1"), upstream.port))
            }
            assertTrue("The fake upstream must observe the drain marker.", upstream.waitForCount(markerDomain, 1, 2_000L))
            assertEquals("The rejected overflow must not reach upstream.", 0, upstream.count(overflowDomain))
        } catch (failure: Throwable) {
            testFailure = failure
            throw failure
        } finally {
            fixture.cleanup(serviceStartRequested, testFailure) {
                heldClient?.close()
            }
        }
    }

    private companion object {
        const val MAX_UNIQUE_QUERIES = 24
    }
}
