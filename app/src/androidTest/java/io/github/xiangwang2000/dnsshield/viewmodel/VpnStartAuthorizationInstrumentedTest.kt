package io.github.xiangwang2000.dnsshield.viewmodel

import android.app.Application
import android.content.ComponentName
import android.content.ContextWrapper
import android.content.Intent
import androidx.lifecycle.ViewModelStore
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.service.DnsVpnService
import io.github.xiangwang2000.dnsshield.service.VpnLifecycleState
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class VpnStartAuthorizationInstrumentedTest {
    @Test
    fun delayedAuthorizationDoesNotToggleAlreadyRunningVpn() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val application = instrumentation.targetContext.applicationContext as Application
        val lifecycle = DnsVpnService.lifecycleStateFlow
        val previousLifecycle = lifecycle.value
        val store = ViewModelStore()
        val actions = mutableListOf<String?>()
        val context = object : ContextWrapper(application) {
            override fun startService(service: Intent): ComponentName? {
                actions += service.action
                return service.component
            }

            override fun startForegroundService(service: Intent): ComponentName? = startService(service)
        }

        try {
            lifecycle.value = VpnLifecycleState.STOPPED
            val viewModel = DnsVpnViewModel(application)
            instrumentation.runOnMainSync {
                store.put("vpn-start-authorization", viewModel)
                viewModel.startVpn(context)
            }
            assertEquals(listOf(DnsVpnService.ACTION_START), actions)

            lifecycle.value = VpnLifecycleState.RUNNING
            withTimeout(5_000L) {
                viewModel.vpnLifecycleState.first { it == VpnLifecycleState.RUNNING }
            }
            instrumentation.runOnMainSync { viewModel.startVpn(context) }
            assertEquals(
                "A late authorization result must not stop an already-running VPN.",
                listOf(DnsVpnService.ACTION_START),
                actions
            )

            instrumentation.runOnMainSync { viewModel.toggleVpn(context) }
            assertEquals(listOf(DnsVpnService.ACTION_START, DnsVpnService.ACTION_STOP), actions)
        } finally {
            instrumentation.runOnMainSync { store.clear() }
            lifecycle.value = previousLifecycle
        }
    }
}
