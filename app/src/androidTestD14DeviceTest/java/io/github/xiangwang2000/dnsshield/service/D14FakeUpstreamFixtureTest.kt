package io.github.xiangwang2000.dnsshield.service

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class D14FakeUpstreamFixtureTest {
    @Test
    fun restoresSettingsAfterQueuedStopFromFailedState() = runBlocking {
        assertTrue("Run only the isolated .d14test target.", BuildConfig.D14_DEVICE_TEST)
        val context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        assertEquals("io.github.xiangwang2000.dnsshield.d14test", context.packageName)
        val lifecycle = DnsVpnService.lifecycleStateFlow
        assertEquals(VpnLifecycleState.STOPPED, lifecycle.value)
        val preferences = context.getSharedPreferences(DnsVpnService.D14_TEST_PREFS_NAME, Context.MODE_PRIVATE)
        val savedPreferences = preferences.all
        val queuedStopContext = object : ContextWrapper(context) {
            override fun startService(service: Intent): ComponentName? {
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
                lifecycle.value = VpnLifecycleState.STOPPED
                cleanup.await()
                assertTrue("Cleanup must wait for the queued stop.", waitedForStop)
            }
            assertEquals(savedPreferences, preferences.all)
        } finally {
            lifecycle.value = VpnLifecycleState.STOPPED
            fixture.cleanup(serviceStartRequested = false, primaryFailure = null)
        }
    }
}
