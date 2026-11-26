package io.github.xiangwang2000.dnsshield.service

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.UserDomainRuleEntity
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Keeps the D14 TUN lifecycle and fixture regressions together in one instrumentation suite. */
@RunWith(AndroidJUnit4::class)
class VpnTunnelRegressionInstrumentedTest {
    @Test
    fun ruleReloadInvalidatesCachedAnswerThroughTun() = runBlocking {
        val context = isolatedD14Context()
        ensureD14VpnConsent(context)
        assertEquals(
            "Stop an existing D14 VPN before running this isolated lifecycle test.",
            VpnLifecycleState.STOPPED,
            DnsVpnService.lifecycleStateFlow.value
        )

        val dao = AppDatabase.getDatabase(context).dnsDao()
        val domain = "d14-rule-${System.nanoTime()}.example.com"
        assertNull("Test domain unexpectedly already has a rule", dao.getUserDomainRule(domain, false))

        val fixture = D14FakeUpstreamFixture(context)
        val upstream = fixture.upstream
        var serviceStartRequested = false
        var ruleInserted = false
        var testFailure: Throwable? = null

        try {
            fixture.install()

            ruleInserted = true
            dao.replaceUserDomainRule(
                UserDomainRuleEntity(domain = domain, action = "BLOCK", includeSubdomains = false)
            )

            serviceStartRequested = true
            ContextCompat.startForegroundService(
                context,
                Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
            )
            d14WaitForLifecycle(VpnLifecycleState.RUNNING, 20_000L)

            assertEquals(3, d14ResponseCode(d14AwaitRcode(domain, 3)))
            assertEquals("A blocked query must not reach the fake upstream.", 0, upstream.count(domain))

            dao.replaceUserDomainRule(
                UserDomainRuleEntity(domain = domain, action = "ALLOW", includeSubdomains = false)
            )
            context.startService(reloadIntent(context))
            d14AssertDnsAnswer(d14AwaitRcode(domain, 0))
            assertTrue("The allowed query must reach the fake upstream.", upstream.waitForCount(domain, 1, 2_000L))

            d14AssertDnsAnswer(d14AwaitRcode(domain, 0))
            assertEquals("A repeated allowed query must use its cache entry.", 1, upstream.count(domain))

            dao.replaceUserDomainRule(
                UserDomainRuleEntity(domain = domain, action = "BLOCK", includeSubdomains = false)
            )
            context.startService(reloadIntent(context))
            assertEquals(3, d14ResponseCode(d14AwaitRcode(domain, 3)))
            assertEquals(
                "A cached positive answer must not survive the BLOCK reload.",
                1,
                upstream.count(domain)
            )
            assertNull("Fake upstream thread failed.", upstream.failure)
        } catch (failure: Throwable) {
            testFailure = failure
            throw failure
        } finally {
            fixture.cleanup(serviceStartRequested, testFailure) {
                if (ruleInserted) dao.deleteUserDomainRule(domain, false)
            }
        }
    }

    private fun reloadIntent(context: Context) =
        Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_RELOAD_DOMAIN_POLICY)

    @Test
    fun rejectsUniqueOverflowAndStopsWithPendingQueries() = runBlocking {
        val context = isolatedD14Context()
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

    @Test
    fun restoresSettingsAfterQueuedStopFromFailedState() = runBlocking {
        val context = isolatedD14Context()
        val lifecycle = DnsVpnService.lifecycleStateFlow
        assertEquals(VpnLifecycleState.STOPPED, lifecycle.value)
        val preferences = context.getSharedPreferences(DnsVpnService.D14_TEST_PREFS_NAME, Context.MODE_PRIVATE)
        val savedPreferences = preferences.all
        val queuedStopActions = mutableListOf<String?>()
        val queuedStopContext = object : ContextWrapper(context) {
            override fun startService(service: Intent): ComponentName? {
                queuedStopActions += service.action
                assertEquals(DnsVpnService.ACTION_STOP, service.action)
                return service.component
            }

            override fun stopService(service: Intent): Boolean =
                throw AssertionError("The queued stop must be allowed to finish before falling back.")
        }
        val fixture = D14FakeUpstreamFixture(queuedStopContext)
        try {
            fixture.install()
            lifecycle.value = VpnLifecycleState.FAILED
            supervisorScope {
                // Deliver STOPPED only after cleanup has begun waiting for the queued stop.
                val cleanup = async(start = CoroutineStart.UNDISPATCHED) {
                    fixture.cleanup(serviceStartRequested = true, primaryFailure = null)
                }
                val waitedForStop = !cleanup.isCompleted
                try {
                    assertTrue("Cleanup must wait for the queued stop.", waitedForStop)
                    assertEquals(listOf(DnsVpnService.ACTION_STOP), queuedStopActions)
                    assertEquals("127.0.0.1", preferences.getString(DnsVpnService.D14_TEST_UPSTREAM_HOST_KEY, null))
                    assertEquals(fixture.upstream.port, preferences.getInt(DnsVpnService.D14_TEST_UPSTREAM_PORT_KEY, -1))
                } finally {
                    lifecycle.value = VpnLifecycleState.STOPPED
                    cleanup.await()
                }
            }
            assertEquals(savedPreferences, preferences.all)
        } finally {
            lifecycle.value = VpnLifecycleState.STOPPED
            fixture.cleanup(serviceStartRequested = false, primaryFailure = null)
        }
    }

    private fun isolatedD14Context(): Context {
        assertTrue("Run only the isolated .d14test target.", BuildConfig.D14_DEVICE_TEST)
        val context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        assertEquals("io.github.xiangwang2000.dnsshield.d14test", context.packageName)
        return context
    }
}
