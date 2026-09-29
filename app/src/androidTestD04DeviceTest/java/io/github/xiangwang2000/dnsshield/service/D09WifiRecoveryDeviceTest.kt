package io.github.xiangwang2000.dnsshield.service

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
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

    private fun hasValidatedWifi(connectivity: ConnectivityManager): Boolean =
        connectivity.allNetworks.any { network ->
            connectivity.getNetworkCapabilities(network)?.let { capabilities ->
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            } == true
        }

    private fun dnsQuery(domain: String): ByteArray =
        (listOf<Byte>(0, 93, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            domain.split('.').flatMap { label ->
                listOf(label.length.toByte()) + label.toByteArray().toList()
            } + listOf<Byte>(0, 0, 1, 0, 1)).toByteArray()
}
