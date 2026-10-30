package io.github.xiangwang2000.dnsshield.service

import android.app.UiAutomation
import android.app.Application
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import io.github.xiangwang2000.dnsshield.viewmodel.DnsVpnViewModel
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class D09WifiRecoveryDeviceTest {
    private lateinit var wifi: NetworkPresenceObserver
    private lateinit var underlays: NetworkPresenceObserver

    @Before fun observeWifi() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val manager = context.getSystemService(ConnectivityManager::class.java)
        // Preserve the original Wi-Fi observer scope, including restricted or untrusted networks.
        wifi = NetworkPresenceObserver(manager, NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            .build())
        underlays = NetworkPresenceObserver(manager, NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build())
    }

    @After fun stopObservingWifi() {
        if (::underlays.isInitialized) underlays.close()
        if (::wifi.isInitialized) wifi.close()
    }

    @Test fun wifiOutageThenValidatedRecoveryRestoresDns() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val automation = instrumentation.uiAutomation
        val store = ViewModelStore()
        val owner = object : ViewModelStoreOwner { override val viewModelStore = store }
        var viewModel: DnsVpnViewModel? = null
        assertTrue(context.packageName.endsWith(".d04test"))
        assertNull(VpnService.prepare(context))
        assertTrue("Wi-Fi must be validated before this test", wifi.awaitInitialMatchingNetwork())
        assertTrue("The underlying-network observer must receive its initial callback", underlays.awaitInitialMatchingNetwork())

        DnsVpnService.setUiForeground(true)
        DnsVpnService.clearLogs()
        ContextCompat.startForegroundService(
            context, Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
        )
        try {
            instrumentation.runOnMainSync {
                viewModel = ViewModelProvider(
                    owner,
                    ViewModelProvider.AndroidViewModelFactory.getInstance(context.applicationContext as Application)
                )[DnsVpnViewModel::class.java]
            }
            withTimeout(30_000) {
                DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING }
            }
            withTimeout(10_000) {
                while (DnsVpnService.liveLogsFlow.value.none { it.contains("[網路狀態] 網路連線正常") }) {
                    delay(50)
                }
            }

            assertNetworkUi(requireNotNull(viewModel), UnderlyingNetworkConnectivity.ONLINE)
            val unavailableStatusesBefore = unavailableStatusCount()
            automation.executeShellCommand("svc wifi disable").close()
            withTimeout(20_000) {
                while (wifi.hasMatchingNetwork()) delay(100)
            }
            assertNoAlternateUnderlay()
            awaitUnavailableStatusAfter(unavailableStatusesBefore)
            // Pre-S VPN callbacks may lose the selected underlay identity and report UNKNOWN.
            val unavailableConnectivity = withTimeout(20_000) {
                DnsVpnService.underlyingNetworkConnectivityFlow.first {
                    it == UnderlyingNetworkConnectivity.OFFLINE || it == UnderlyingNetworkConnectivity.UNKNOWN
                }
            }
            assertNetworkUi(requireNotNull(viewModel), unavailableConnectivity)
            automation.executeShellCommand("svc wifi enable").close()
            withTimeout(40_000) {
                while (!wifi.hasMatchingNetwork()) delay(250)
            }
            withTimeout(20_000) {
                DnsVpnService.liveLogsFlow.first { lines ->
                    lines.any { it.contains("[網路恢復] 非 VPN 網路已就緒") }
                }
            }
            assertNetworkUi(requireNotNull(viewModel), UnderlyingNetworkConnectivity.ONLINE)
            val query = dnsQuery("example.com")
            val parsed = (DnsMessageValidator.parseQuery(query) as DnsQueryParseResult.Valid).query
            DatagramSocket().use { client ->
                client.soTimeout = 8_000
                client.connect(InetAddress.getByName("10.0.0.1"), 53)
                client.send(DatagramPacket(query, query.size))
                val response = DatagramPacket(ByteArray(4096), 4096)
                client.receive(response)
                val payload = response.data.copyOf(response.length)
                assertTrue("Recovered DNS response must match the query", DnsMessageValidator.isValidResponse(payload, parsed))
                assertEquals("Recovered upstream query must succeed", 0, payload[3].toInt() and 15)
            }
            println("D09_WIFI_RECOVERY=Wi-Fi unavailable observed, validated Wi-Fi recovered, DNS response succeeded")
        } finally {
            try {
                automation.executeShellCommand("svc wifi enable").close()
                withTimeout(40_000) {
                    while (!wifi.hasMatchingNetwork()) delay(250)
                }
            } finally {
                try {
                    context.startService(
                        Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)
                    )
                    withTimeout(15_000) {
                        DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED }
                        DnsVpnService.underlyingNetworkConnectivityFlow.first { it == UnderlyingNetworkConnectivity.UNKNOWN }
                        viewModel?.let { model ->
                            model.uiState.first {
                                it.vpnLifecycleState == VpnLifecycleState.STOPPED &&
                                    it.networkConnectivity == UnderlyingNetworkConnectivity.UNKNOWN
                            }
                        }
                    }
                } finally {
                    DnsVpnService.setUiForeground(false)
                    instrumentation.runOnMainSync { store.clear() }
                }
            }
        }
    }

    @Test fun startingOfflineKeepsProtectionEnabledAndRecoversWhenWifiReturns() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val automation = instrumentation.uiAutomation
        assertTrue(context.packageName.endsWith(".d04test"))
        assertNull(VpnService.prepare(context))
        assertTrue("Wi-Fi must be validated before this test", wifi.awaitInitialMatchingNetwork())
        assertTrue("The underlying-network observer must receive its initial callback", underlays.awaitInitialMatchingNetwork())
        val store = ViewModelStore()
        val owner = object : ViewModelStoreOwner { override val viewModelStore = store }
        var viewModel: DnsVpnViewModel? = null
        DnsVpnService.setUiForeground(true)
        try {
            automation.executeShellCommand("svc wifi disable").close()
            withTimeout(20_000) { while (wifi.hasMatchingNetwork()) delay(100) }
            assertNoAlternateUnderlay()
            instrumentation.runOnMainSync {
                viewModel = ViewModelProvider(
                    owner,
                    ViewModelProvider.AndroidViewModelFactory.getInstance(context.applicationContext as Application)
                )[DnsVpnViewModel::class.java]
            }
            ContextCompat.startForegroundService(
                context, Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
            )
            withTimeout(30_000) {
                DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING }
                requireNotNull(viewModel).uiState.first {
                    it.vpnLifecycleState == VpnLifecycleState.RUNNING &&
                        it.networkConnectivity != UnderlyingNetworkConnectivity.ONLINE
                }
            }
            // Android may report UNKNOWN before a selected underlay is observable.
            assertFalse(DnsVpnService.underlyingNetworkConnectivityFlow.value == UnderlyingNetworkConnectivity.ONLINE)
            automation.executeShellCommand("svc wifi enable").close()
            withTimeout(40_000) { while (!wifi.hasMatchingNetwork()) delay(250) }
            assertNetworkUi(requireNotNull(viewModel), UnderlyingNetworkConnectivity.ONLINE)
            assertRecoveredDns(0xD090, null)
        } finally {
            try {
                automation.executeShellCommand("svc wifi enable").close()
                withTimeout(40_000) { while (!wifi.hasMatchingNetwork()) delay(250) }
            } finally {
                try {
                    context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
                    withTimeout(15_000) {
                        DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED }
                        DnsVpnService.underlyingNetworkConnectivityFlow.first { it == UnderlyingNetworkConnectivity.UNKNOWN }
                    }
                } finally {
                    DnsVpnService.setUiForeground(false)
                    instrumentation.runOnMainSync { store.clear() }
                }
            }
        }
    }

    @Test fun repeatedWifiAndAirplaneRecoveryRestoreDns() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val automation = instrumentation.uiAutomation
        assertTrue(context.packageName.endsWith(".d04test"))
        assertNull(VpnService.prepare(context))
        assertTrue("Wi-Fi must be validated before this test", wifi.awaitInitialMatchingNetwork())
        val originalWifiEnabled = runShell(automation, "settings get global wifi_on").trim() == "1"
        val originalAirplaneMode = runShell(automation, "settings get global airplane_mode_on").trim() == "1"
        assertTrue("Wi-Fi must be enabled before this test", originalWifiEnabled)
        assertFalse("Start with airplane mode off", originalAirplaneMode)

        DnsVpnService.setUiForeground(true)
        DnsVpnService.clearLogs()
        ContextCompat.startForegroundService(
            context, Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
        )
        val transactionIdBase = System.nanoTime().toInt() and 0xFFFF
        try {
            withTimeout(30_000) {
                DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING }
            }
            withTimeout(10_000) {
                DnsVpnService.liveLogsFlow.first { lines ->
                    lines.any { it.contains("[網路狀態] 網路連線正常") }
                }
            }

            var recoveryGeneration: Long? = latestRecoveryGeneration(DnsVpnService.liveLogsFlow.value)
            repeat(3) { cycle ->
                recoveryGeneration = recoverAfterWifiToggle(
                    automation, cycle, recoveryGeneration, transactionIdBase
                )
            }

            val offlineLogs = unavailableStatusCount()
            setAirplaneMode(automation, true)
            runShell(automation, "svc wifi disable")
            awaitWifiUnavailable()
            awaitUnavailableStatusAfter(offlineLogs)
            val logsBeforeAirplaneRecovery = DnsVpnService.liveLogsFlow.value
            val airplaneGenerationBeforeRecovery = latestRecoveryGeneration(logsBeforeAirplaneRecovery) ?: recoveryGeneration
            val airplaneRecoveryCountBefore = recoveryLogCount(logsBeforeAirplaneRecovery)
            setAirplaneMode(automation, false)
            runShell(automation, "svc wifi enable")
            awaitValidatedWifi()
            recoveryGeneration = awaitRecoveryGenerationAfter(airplaneGenerationBeforeRecovery, airplaneRecoveryCountBefore)
            val queryId = (transactionIdBase + 3) and 0xFFFF
            assertRecoveredDns(queryId, recoveryGeneration)
            println("D09_AIRPLANE_WIFI_RECOVERY=airplane+Wi-Fi-off -> airplane-off+Wi-Fi-on, generation $recoveryGeneration, DNS response succeeded")
        } finally {
            try {
                setAirplaneMode(automation, originalAirplaneMode)
            } finally {
                try {
                    runShell(automation, "svc wifi ${if (originalWifiEnabled) "enable" else "disable"}")
                    if (originalWifiEnabled && !originalAirplaneMode) awaitValidatedWifi()
                } finally {
                    context.startService(
                        Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)
                    )
                    withTimeout(15_000) {
                        DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED }
                    }
                    DnsVpnService.setUiForeground(false)
                }
            }
        }
    }

    private suspend fun assertNoAlternateUnderlay() {
        val offline = withTimeoutOrNull(5_000) {
            while (underlays.hasMatchingNetwork()) delay(50)
            true
        } == true
        assertTrue("Offline scenarios require Wi-Fi-only connectivity without an alternate internet network", offline)
    }

    private suspend fun assertNetworkUi(viewModel: DnsVpnViewModel, expected: UnderlyingNetworkConnectivity) {
        withTimeout(20_000) {
            DnsVpnService.underlyingNetworkConnectivityFlow.first { it == expected }
            val state = viewModel.uiState.first { it.networkConnectivity == expected }
            assertEquals("Network changes must keep VPN protection enabled", VpnLifecycleState.RUNNING, state.vpnLifecycleState)
        }
    }

    private suspend fun recoverAfterWifiToggle(
        automation: UiAutomation,
        cycle: Int,
        previousGeneration: Long?,
        transactionIdBase: Int
    ): Long {
        val offlineLogs = unavailableStatusCount()
        runShell(automation, "svc wifi disable")
        awaitWifiUnavailable()
        awaitUnavailableStatusAfter(offlineLogs)
        val logsBeforeRecovery = DnsVpnService.liveLogsFlow.value
        val generationBeforeRecovery = latestRecoveryGeneration(logsBeforeRecovery) ?: previousGeneration
        val recoveryCountBefore = recoveryLogCount(logsBeforeRecovery)

        runShell(automation, "svc wifi enable")
        awaitValidatedWifi()
        val generation = awaitRecoveryGenerationAfter(generationBeforeRecovery, recoveryCountBefore)
        assertRecoveredDns((transactionIdBase + cycle) and 0xFFFF, generation)
        println("D09_WIFI_RECOVERY=cycle ${cycle + 1}, generation $generation, DNS response succeeded")
        return generation
    }

    private suspend fun assertRecoveredDns(queryId: Int, generation: Long?) {
        val before = DnsVpnService.diagnosticsFlow.value
        val query = dnsQuery("example.com", queryId)
        val parsed = (DnsMessageValidator.parseQuery(query) as DnsQueryParseResult.Valid).query
        DatagramSocket().use { client ->
            client.soTimeout = 8_000
            client.connect(InetAddress.getByName("10.0.0.1"), 53)
            client.send(DatagramPacket(query, query.size))
            val response = DatagramPacket(ByteArray(4096), 4096)
            client.receive(response)
            val payload = response.data.copyOf(response.length)
            assertTrue(
                "Recovered DNS response must match transaction $queryId",
                DnsMessageValidator.isValidResponse(payload, parsed)
            )
            assertEquals("Recovered DNS response must succeed", 0, payload[3].toInt() and 15)
        }
        withTimeout(5_000) {
            DnsVpnService.diagnosticsFlow.first {
                it.received > before.received && it.resolved > before.resolved
            }
        }
        val recovery = generation?.let { "after observing generation $it" } ?: "after network recovery"
        println("D09_TUN_DNS=transaction $queryId succeeded $recovery")
    }

    private suspend fun awaitWifiUnavailable() {
        withTimeout(20_000) {
            while (wifi.hasMatchingNetwork()) delay(100)
        }
    }

    private suspend fun awaitValidatedWifi() {
        withTimeout(40_000) {
            while (!wifi.hasMatchingNetwork()) delay(250)
        }
    }

    private fun isUnavailableNetworkStatus(message: String): Boolean =
        message.contains("[網路狀態] 目前沒有可用網路") ||
            message.contains("[網路狀態] 正在確認目前選用的非 VPN 網路")

    private fun unavailableStatusCount(): Int =
        DnsVpnService.liveLogsFlow.value.count { isUnavailableNetworkStatus(it) }

    private suspend fun awaitUnavailableStatusAfter(previousCount: Int) {
        withTimeout(20_000) {
            DnsVpnService.liveLogsFlow.first { lines ->
                lines.count { isUnavailableNetworkStatus(it) } > previousCount
            }
        }
    }

    private suspend fun awaitRecoveryGenerationAfter(
        previousGeneration: Long?,
        previousRecoveryCount: Int
    ): Long {
        val lines = withTimeout(20_000) {
            DnsVpnService.liveLogsFlow.first { messages ->
                val generation = latestRecoveryGeneration(messages)
                recoveryLogCount(messages) > previousRecoveryCount &&
                    generation != null && (previousGeneration == null || generation > previousGeneration)
            }
        }
        return requireNotNull(latestRecoveryGeneration(lines))
    }

    private fun recoveryLogCount(lines: List<String>): Int =
        lines.count { it.contains("[網路恢復] 非 VPN 網路已就緒（generation ") }

    private fun latestRecoveryGeneration(lines: List<String>): Long? {
        val pattern = Regex("\\[網路恢復\\] 非 VPN 網路已就緒（generation (\\d+)）")
        return lines.mapNotNull { pattern.find(it)?.groupValues?.get(1)?.toLongOrNull() }.maxOrNull()
    }

    private fun setAirplaneMode(automation: UiAutomation, enabled: Boolean) {
        val state = if (enabled) "1" else "0"
        runShell(automation, "settings put global airplane_mode_on $state")
        runShell(automation, "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state $enabled")
        check(runShell(automation, "settings get global airplane_mode_on").trim() == state) {
            "Android did not apply airplane mode state $state"
        }
    }

    private fun runShell(automation: UiAutomation, command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(automation.executeShellCommand(command))
            .bufferedReader().use { it.readText() }

    private fun dnsQuery(domain: String, transactionId: Int = 93): ByteArray =
        (listOf((transactionId shr 8).toByte(), transactionId.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            domain.split('.').flatMap { label ->
                listOf(label.length.toByte()) + label.toByteArray().toList()
            } + listOf<Byte>(0, 0, 1, 0, 1)).toByteArray()
}

private class NetworkPresenceObserver(
    private val connectivity: ConnectivityManager,
    request: NetworkRequest
) {
    private val matchingNetworks = ConcurrentHashMap.newKeySet<Network>()
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            matchingNetworks.add(network)
        }

        override fun onLost(network: Network) {
            matchingNetworks.remove(network)
        }
    }

    init {
        connectivity.registerNetworkCallback(request, callback)
    }

    fun hasMatchingNetwork(): Boolean = matchingNetworks.isNotEmpty()

    // Registration delivers the initially matching networks asynchronously.
    suspend fun awaitInitialMatchingNetwork(): Boolean = withTimeoutOrNull(5_000) {
        while (!hasMatchingNetwork()) delay(25)
        true
    } ?: false

    fun close() {
        connectivity.unregisterNetworkCallback(callback)
    }
}
