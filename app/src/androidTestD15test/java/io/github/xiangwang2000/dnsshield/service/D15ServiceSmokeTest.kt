package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class D15ServiceSmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val targetContext = instrumentation.targetContext
    private val userIntent = targetContext.getSharedPreferences(
        VPN_SERVICE_PREFERENCES,
        Context.MODE_PRIVATE
    )

    @Before
    fun resetState(): Unit = runBlocking {
        targetContext.startService(serviceIntent(DnsVpnService.ACTION_STOP))
        waitForLifecycle(VpnLifecycleState.STOPPED)
        userIntent.edit().clear().commit()
    }

    @After
    fun cleanup(): Unit = runBlocking {
        targetContext.startService(serviceIntent(DnsVpnService.ACTION_STOP))
        waitForLifecycle(VpnLifecycleState.STOPPED)
        userIntent.edit().clear().commit()
    }

    @Test
    fun explicitStartAndStopUseOnlyTheIsolatedD15PackageState() = runBlocking {
        assertNotEquals("io.github.xiangwang2000.dnsshield", targetContext.packageName)
        assertTrue(targetContext.packageName.endsWith(".d15test"))
        assertNull("Approve the isolated D15 VPN before execution", VpnService.prepare(targetContext))

        ContextCompat.startForegroundService(targetContext, serviceIntent(DnsVpnService.ACTION_START))
        waitForDesiredState(expected = true)
        waitForLifecycle(VpnLifecycleState.RUNNING)

        targetContext.startService(serviceIntent(DnsVpnService.ACTION_STOP))
        waitForDesiredState(expected = false)
        waitForLifecycle(VpnLifecycleState.STOPPED)
    }

    @Test
    fun explicitStopSuppressesNullActionRecovery() = runBlocking {
        assertNull("Approve the isolated D15 VPN before execution", VpnService.prepare(targetContext))
        ContextCompat.startForegroundService(targetContext, serviceIntent(DnsVpnService.ACTION_START))
        waitForLifecycle(VpnLifecycleState.RUNNING)
        targetContext.startService(serviceIntent(DnsVpnService.ACTION_STOP))
        waitForLifecycle(VpnLifecycleState.STOPPED)
        assertEquals(false, userIntent.getBoolean(VPN_DESIRED_ENABLED_KEY, true))

        ContextCompat.startForegroundService(targetContext, Intent(targetContext, DnsVpnService::class.java))
        kotlinx.coroutines.delay(500)
        assertEquals(VpnLifecycleState.STOPPED, DnsVpnService.lifecycleStateFlow.value)
        assertEquals(false, userIntent.getBoolean(VPN_DESIRED_ENABLED_KEY, true))

        ContextCompat.startForegroundService(targetContext, serviceIntent(VpnService.SERVICE_INTERFACE))
        kotlinx.coroutines.delay(500)
        assertEquals(VpnLifecycleState.STOPPED, DnsVpnService.lifecycleStateFlow.value)
        assertEquals(false, userIntent.getBoolean(VPN_DESIRED_ENABLED_KEY, true))
    }

    @Test
    fun systemVpnServiceActionRestoresPersistedUserIntent() = runBlocking {
        assertNull("Approve the isolated D15 VPN before execution", VpnService.prepare(targetContext))
        userIntent.edit()
            .putBoolean(VPN_DESIRED_ENABLED_KEY, true)
            .putBoolean(VPN_EXPLICIT_CHOICE_KEY, true)
            .commit()

        ContextCompat.startForegroundService(targetContext, serviceIntent(VpnService.SERVICE_INTERFACE))
        waitForLifecycle(VpnLifecycleState.RUNNING)
        assertEquals(true, userIntent.getBoolean(VPN_DESIRED_ENABLED_KEY, false))
    }

    private fun serviceIntent(action: String): Intent =
        Intent(targetContext, DnsVpnService::class.java).setAction(action)

    private fun waitForDesiredState(expected: Boolean) {
        repeat(40) {
            if (userIntent.getBoolean(VPN_DESIRED_ENABLED_KEY, false) == expected) {
                return
            }
            SystemClock.sleep(50)
        }
        assertEquals(
            "D15 service intent did not persist desiredEnabled=$expected",
            expected,
            userIntent.getBoolean(VPN_DESIRED_ENABLED_KEY, !expected)
        )
    }

    private suspend fun waitForLifecycle(expected: VpnLifecycleState) {
        withTimeout(15_000) {
            DnsVpnService.lifecycleStateFlow.first { it == expected }
        }
    }
}
