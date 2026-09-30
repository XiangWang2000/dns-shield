package io.github.xiangwang2000.dnsshield.service

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

/** Run separately after revoking the isolated D15 VPN in system settings. */
@RunWith(AndroidJUnit4::class)
class D15UnapprovedStartTest {
    @Test
    @Suppress("DEPRECATION")
    fun failedStartsAndLateRecoveryLeaveNoForegroundKeeper() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertNotNull("Revoke the isolated D15 VPN first", VpnService.prepare(context))
        val preferences = context.getSharedPreferences(VPN_SERVICE_PREFERENCES, Context.MODE_PRIVATE)
        try {
            for (action in listOf(DnsVpnService.ACTION_START, DnsVpnService.ACTION_RESTART)) {
                ContextCompat.startForegroundService(context, Intent(context, DnsVpnService::class.java).setAction(action))
                withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.FAILED } }
                delay(1_000)
                assertFalse("Failed startup must remove the recovery keeper", hasKeeper(context))
            }
            VpnUserIntentStore(preferences).markAuthorizationRevoke()
            context.startService(Intent(context, VpnRecoveryService::class.java))
            delay(1_000)
            assertFalse("A late recovery start must honor revoke", hasKeeper(context))
        } finally {
            context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
            withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED } }
        }
    }

    @Suppress("DEPRECATION")
    private fun hasKeeper(context: Context): Boolean =
        context.getSystemService(ActivityManager::class.java).getRunningServices(20)
            .any { it.service.className == VpnRecoveryService::class.java.name }
}
