package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.provider.Settings
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.D04VpnConsentActivity
import java.util.Collections
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters

@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class VpnLifecycleDeviceTest {
    @Test
    fun test01UnapprovedStartFailsThenConsentAllowsRetry() = runBlocking {
        val context = targetContext()
        assertNotNull(
            "Uninstall and reinstall .d04test before running the first consent test.",
            VpnService.prepare(context)
        )

        startForeground(context, DnsVpnService.ACTION_START)
        awaitState(VpnLifecycleState.FAILED)

        ensureVpnConsent(context)
        startForeground(context, DnsVpnService.ACTION_START)
        awaitState(VpnLifecycleState.RUNNING)
        stop(context)
        awaitState(VpnLifecycleState.STOPPED)
    }

    @Test
    fun test02RapidStartThenStopDoesNotReachRunning() = runBlocking {
        val context = targetContext()
        ensureVpnConsent(context)
        stop(context)
        awaitState(VpnLifecycleState.STOPPED)

        val observed = Collections.synchronizedList(mutableListOf<VpnLifecycleState>())
        val collector = CoroutineScope(Dispatchers.Default).launch(start = CoroutineStart.UNDISPATCHED) {
            DnsVpnService.lifecycleStateFlow.collect { state ->
                synchronized(observed) { observed.add(state) }
            }
        }
        try {
            assertNotNull(ContextCompat.startForegroundService(
                context,
                Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
            ))
            assertNotNull(context.startService(
                Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)
            ))
            delay(1_000)
            val sawRunning = synchronized(observed) {
                observed.contains(VpnLifecycleState.RUNNING)
            }
            assertFalse("A queued stop must invalidate startup before the tunnel reaches RUNNING.", sawRunning)
            assertEquals(VpnLifecycleState.STOPPED, DnsVpnService.lifecycleStateFlow.value)
        } finally {
            collector.cancelAndJoin()
        }
    }

    @Test
    fun test03RepeatedRestartsAndStopsReturnToStableStates() = runBlocking {
        val context = targetContext()
        ensureVpnConsent(context)

        startForeground(context, DnsVpnService.ACTION_START)
        awaitState(VpnLifecycleState.RUNNING)

        repeat(3) {
            val stopping = async(start = CoroutineStart.UNDISPATCHED) {
                withTimeout(15_000) {
                    DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPING }
                }
            }
            startForeground(context, DnsVpnService.ACTION_RESTART)
            stopping.await()
            awaitState(VpnLifecycleState.RUNNING)
        }

        repeat(5) {
            startForeground(context, DnsVpnService.ACTION_START)
        }
        delay(500)
        assertEquals(VpnLifecycleState.RUNNING, DnsVpnService.lifecycleStateFlow.value)

        stop(context)
        awaitState(VpnLifecycleState.STOPPED)
    }

    @Test
    fun test04RevokingVpnConsentStopsTheRunningTunnel() = runBlocking {
        val context = targetContext()
        ensureVpnConsent(context)
        startForeground(context, DnsVpnService.ACTION_START)
        awaitState(VpnLifecycleState.RUNNING)

        println("D04_DEVICE_ACTION=Start VPN in a different package to revoke the isolated .d04test VPN.")
        context.startActivity(
            Intent(Settings.ACTION_VPN_SETTINGS)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        val stopped = withTimeoutOrNull(60_000) {
            DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED }
            true
        } ?: false
        if (!stopped) {
            val consentRequired = VpnService.prepare(context) != null
            throw AssertionError(
                "System VPN revoke timed out: state=${DnsVpnService.lifecycleStateFlow.value}, " +
                    "consentRequired=$consentRequired"
            )
        }
        assertEquals(VpnLifecycleState.STOPPED, DnsVpnService.lifecycleStateFlow.value)
        println("D04_VPN_PERMISSION_RETAINED_AFTER_REVOKE=${VpnService.prepare(context) == null}")
    }

    private suspend fun ensureVpnConsent(context: Context) {
        if (VpnService.prepare(context) == null) return
        println("D04_DEVICE_ACTION=Approve the system VPN request for DNS Shield D04 Test.")
        context.startActivity(
            Intent(context, D04VpnConsentActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        withTimeout(120_000) {
            while (VpnService.prepare(context) != null) delay(250)
        }
    }

    private fun targetContext(): Context =
        InstrumentationRegistry.getInstrumentation().targetContext

    private fun startForeground(context: Context, action: String) {
        ContextCompat.startForegroundService(
            context,
            Intent(context, DnsVpnService::class.java).setAction(action)
        )
    }

    private fun stop(context: Context) {
        context.startService(
            Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)
        )
    }

    private suspend fun awaitState(expected: VpnLifecycleState) {
        withTimeout(30_000) {
            DnsVpnService.lifecycleStateFlow.first { it == expected }
        }
    }
}
