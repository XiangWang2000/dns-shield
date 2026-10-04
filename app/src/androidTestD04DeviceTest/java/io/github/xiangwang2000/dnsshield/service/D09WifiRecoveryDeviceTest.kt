package io.github.xiangwang2000.dnsshield.service

import android.app.UiAutomation
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class D09WifiRecoveryDeviceTest {
    @Test fun wifiOutageThenValidatedRecoveryRestoresDns() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val automation = instrumentation.uiAutomation
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        assertTrue(context.packageName.endsWith(".d04test"))
        assertNull(VpnService.prepare(context))
        assertTrue("Wi-Fi must be validated before this test", hasValidatedWifi(connectivity))

        DnsVpnService.setUiForeground(true)
        DnsVpnService.clearLogs()
        ContextCompat.startForegroundService(
            context, Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
        )
        try {
            withTimeout(30_000) {
                DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING }
            }
            withTimeout(10_000) {
                while (DnsVpnService.liveLogsFlow.value.none { it.contains("[網路狀態] 網路連線正常") }) {
                    delay(50)
                }
            }

            automation.executeShellCommand("svc wifi disable").close()
            withTimeout(20_000) {
                while (hasValidatedWifi(connectivity)) delay(100)
            }
            withTimeout(20_000) {
                DnsVpnService.liveLogsFlow.first { lines ->
                    lines.any { it.contains("[網路狀態] 目前沒有可用網路") }
                }
            }

            automation.executeShellCommand("svc wifi enable").close()
            withTimeout(40_000) {
                while (!hasValidatedWifi(connectivity)) delay(250)
            }
            withTimeout(20_000) {
                DnsVpnService.liveLogsFlow.first { lines ->
                    lines.any { it.contains("[網路恢復] 非 VPN 網路已就緒") }
                }
            }
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
            println("D09_WIFI_RECOVERY=offline observed, validated Wi-Fi recovered, DNS response succeeded")
        } finally {
            try {
                automation.executeShellCommand("svc wifi enable").close()
                withTimeout(40_000) {
                    while (!hasValidatedWifi(connectivity)) delay(250)
                }
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

    @Test fun repeatedWifiAndAirplaneRecoveryRestoreDns() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val automation = instrumentation.uiAutomation
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        assertTrue(context.packageName.endsWith(".d04test"))
        assertNull(VpnService.prepare(context))
        assertTrue("Wi-Fi must be validated before this test", hasValidatedWifi(connectivity))
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
                    automation, connectivity, cycle, recoveryGeneration, transactionIdBase
                )
            }

            val offlineLogs = offlineLogCount()
            setAirplaneMode(automation, true)
            runShell(automation, "svc wifi disable")
            awaitWifiUnavailable(connectivity)
            awaitOfflineLogAfter(offlineLogs)
            val logsBeforeAirplaneRecovery = DnsVpnService.liveLogsFlow.value
            val airplaneGenerationBeforeRecovery = latestRecoveryGeneration(logsBeforeAirplaneRecovery) ?: recoveryGeneration
            val airplaneRecoveryCountBefore = recoveryLogCount(logsBeforeAirplaneRecovery)
            setAirplaneMode(automation, false)
            runShell(automation, "svc wifi enable")
            awaitValidatedWifi(connectivity)
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
                    if (originalWifiEnabled && !originalAirplaneMode) awaitValidatedWifi(connectivity)
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

    private suspend fun recoverAfterWifiToggle(
        automation: UiAutomation,
        connectivity: ConnectivityManager,
        cycle: Int,
        previousGeneration: Long?,
        transactionIdBase: Int
    ): Long {
        val offlineLogs = offlineLogCount()
        runShell(automation, "svc wifi disable")
        awaitWifiUnavailable(connectivity)
        awaitOfflineLogAfter(offlineLogs)
        val logsBeforeRecovery = DnsVpnService.liveLogsFlow.value
        val generationBeforeRecovery = latestRecoveryGeneration(logsBeforeRecovery) ?: previousGeneration
        val recoveryCountBefore = recoveryLogCount(logsBeforeRecovery)

        runShell(automation, "svc wifi enable")
        awaitValidatedWifi(connectivity)
        val generation = awaitRecoveryGenerationAfter(generationBeforeRecovery, recoveryCountBefore)
        assertRecoveredDns((transactionIdBase + cycle) and 0xFFFF, generation)
        println("D09_WIFI_RECOVERY=cycle ${cycle + 1}, generation $generation, DNS response succeeded")
        return generation
    }

    private suspend fun assertRecoveredDns(queryId: Int, generation: Long) {
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
        println("D09_TUN_DNS=transaction $queryId succeeded after observing generation $generation")
    }

    private suspend fun awaitWifiUnavailable(connectivity: ConnectivityManager) {
        withTimeout(20_000) {
            while (hasValidatedWifi(connectivity)) delay(100)
        }
    }

    private suspend fun awaitValidatedWifi(connectivity: ConnectivityManager) {
        withTimeout(40_000) {
            while (!hasValidatedWifi(connectivity)) delay(250)
        }
    }

    private fun offlineLogCount(): Int =
        DnsVpnService.liveLogsFlow.value.count { it.contains("[網路狀態] 目前沒有可用網路") }

    private suspend fun awaitOfflineLogAfter(previousCount: Int) {
        withTimeout(20_000) {
            DnsVpnService.liveLogsFlow.first { lines ->
                lines.count { it.contains("[網路狀態] 目前沒有可用網路") } > previousCount
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

    private fun hasValidatedWifi(connectivity: ConnectivityManager): Boolean =
        connectivity.allNetworks.any { network ->
            connectivity.getNetworkCapabilities(network)?.let { capabilities ->
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            } == true
        }

    private fun dnsQuery(domain: String, transactionId: Int = 93): ByteArray =
        (listOf((transactionId shr 8).toByte(), transactionId.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            domain.split('.').flatMap { label ->
                listOf(label.length.toByte()) + label.toByteArray().toList()
            } + listOf<Byte>(0, 0, 1, 0, 1)).toByteArray()
}