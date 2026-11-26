package io.github.xiangwang2000.dnsshield.viewmodel

import android.app.Activity
import android.app.Instrumentation
import android.content.ComponentName
import android.content.ContextWrapper
import android.content.Intent
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.compose.setContent
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalContext
import androidx.core.app.ActivityOptionsCompat
import androidx.lifecycle.ViewModelProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.DnsShieldDashboard
import io.github.xiangwang2000.dnsshield.MainActivity
import io.github.xiangwang2000.dnsshield.service.DnsVpnService
import io.github.xiangwang2000.dnsshield.service.VpnLifecycleState
import io.github.xiangwang2000.dnsshield.ui.theme.MyApplicationTheme
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class VpnStartAuthorizationInstrumentedTest {
    @Test
    fun delayedAuthorizationDoesNotToggleAlreadyRunningVpn() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val lifecycle = DnsVpnService.lifecycleStateFlow
        assertEquals("Run the authorization test with the VPN stopped.", VpnLifecycleState.STOPPED, lifecycle.value)
        val actions = mutableListOf<String?>()
        val consentRequests = mutableListOf<Int>()
        val consentIntent = Intent("io.github.xiangwang2000.dnsshield.test.VPN_CONSENT")
        val registry = object : ActivityResultRegistry(), ActivityResultRegistryOwner {
            override val activityResultRegistry: ActivityResultRegistry get() = this

            override fun <I, O> onLaunch(
                requestCode: Int,
                contract: ActivityResultContract<I, O>,
                input: I,
                options: ActivityOptionsCompat?
            ) {
                when (contract) {
                    is ActivityResultContracts.RequestPermission -> dispatchResult(requestCode, true)
                    is ActivityResultContracts.StartActivityForResult -> consentRequests += requestCode
                }
            }
        }

        var activity: MainActivity? = null
        try {
            val dashboard = instrumentation.startActivitySync(
                Intent(instrumentation.targetContext, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ) as MainActivity
            activity = dashboard
            val context = object : ContextWrapper(dashboard) {
                override fun startService(service: Intent): ComponentName? {
                    actions += service.action
                    return service.component
                }

                override fun startForegroundService(service: Intent): ComponentName? = startService(service)
            }
            lateinit var viewModel: DnsVpnViewModel
            instrumentation.runOnMainSync {
                viewModel = ViewModelProvider(dashboard)[DnsVpnViewModel::class.java]
                dashboard.setContent {
                    CompositionLocalProvider(
                        LocalActivityResultRegistryOwner provides registry,
                        LocalContext provides context
                    ) {
                        MyApplicationTheme {
                            DnsShieldDashboard(viewModel = viewModel, prepareVpn = { consentIntent })
                        }
                    }
                }
            }

            clickPowerButton(instrumentation)
            dispatchApproval(instrumentation, registry, consentRequests.single())
            assertEquals(listOf(DnsVpnService.ACTION_START), actions)

            clickPowerButton(instrumentation)
            assertEquals(2, consentRequests.size)
            lifecycle.value = VpnLifecycleState.RUNNING
            withTimeout(5_000L) {
                viewModel.vpnLifecycleState.first { it == VpnLifecycleState.RUNNING }
            }
            dispatchApproval(instrumentation, registry, consentRequests.last())
            assertEquals("The late result must not ask for consent again.", 2, consentRequests.size)
            assertEquals(
                "A late authorization result must not stop an already-running VPN.",
                listOf(DnsVpnService.ACTION_START),
                actions
            )

            instrumentation.runOnMainSync { viewModel.toggleVpn(context) }
            assertEquals(listOf(DnsVpnService.ACTION_START, DnsVpnService.ACTION_STOP), actions)
        } finally {
            instrumentation.runOnMainSync {
                lifecycle.value = VpnLifecycleState.STOPPED
                activity?.finish()
            }
        }
    }

    private fun dispatchApproval(
        instrumentation: Instrumentation,
        registry: ActivityResultRegistry,
        requestCode: Int
    ) {
        var delivered = false
        instrumentation.runOnMainSync {
            delivered = registry.dispatchResult(requestCode, Activity.RESULT_OK, null)
        }
        assertTrue("The VPN authorization result must reach the dashboard.", delivered)
    }

    private fun clickPowerButton(instrumentation: Instrumentation) {
        fun findPowerButton(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
            if (node.viewIdResourceName == "power_button") return node
            for (index in 0 until node.childCount) {
                node.getChild(index)?.let { findPowerButton(it)?.let { found -> return found } }
            }
            return null
        }

        val deadline = SystemClock.elapsedRealtime() + 5_000L
        while (SystemClock.elapsedRealtime() < deadline) {
            val button = instrumentation.uiAutomation.rootInActiveWindow?.let(::findPowerButton)
            if (button?.refresh() == true && button.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
                instrumentation.waitForIdleSync()
                return
            }
            SystemClock.sleep(25L)
        }
        throw AssertionError("The VPN power button was not clickable.")
    }
}
