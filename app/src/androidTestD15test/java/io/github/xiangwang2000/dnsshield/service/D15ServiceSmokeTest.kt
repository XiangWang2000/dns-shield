package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
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
    fun resetState() {
        targetContext.stopService(serviceIntent(DnsVpnService.ACTION_STOP))
        userIntent.edit().clear().commit()
    }

    @After
    fun cleanup() {
        targetContext.stopService(serviceIntent(DnsVpnService.ACTION_STOP))
        userIntent.edit().clear().commit()
    }

    @Test
    fun explicitStartAndStopUseOnlyTheIsolatedD15PackageState() {
        assertNotEquals("io.github.xiangwang2000.dnsshield", targetContext.packageName)
        assertTrue(targetContext.packageName.endsWith(".d15test"))

        ContextCompat.startForegroundService(targetContext, serviceIntent(DnsVpnService.ACTION_START))
        waitForDesiredState(expected = true)

        targetContext.startService(serviceIntent(DnsVpnService.ACTION_STOP))
        waitForDesiredState(expected = false)
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
}
