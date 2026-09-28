package io.github.xiangwang2000.dnsshield.service

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.MainActivity
import java.net.InetSocketAddress
import java.net.Socket
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
class DnsDiagnosticsDeviceTest {
    @Test fun backgroundQueryAppearsWhenDashboardReturns() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        assertTrue(context.packageName.endsWith(".d04test"))
        assertNull(VpnService.prepare(context))
        ContextCompat.startForegroundService(
            context,
            Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
        )
        withTimeout(30_000) {
            DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING }
        }
        try {
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            withTimeout(10_000) {
                while (connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != true) {
                    delay(25)
                }
            }
            context.startActivity(
                Intent(context, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            )
            assertTrue("Diagnostics card was not rendered", waitForDiagnosticsCard())

            DnsVpnService.clearLogs()
            withTimeout(5_000) { DnsVpnService.diagnosticsFlow.first { it.received == 0L } }
            automation.executeShellCommand("input keyevent HOME").close()
            Thread.sleep(700)
            val backgroundSnapshot = DnsVpnService.diagnosticsFlow.value

            Socket().use { socket ->
                socket.soTimeout = 10_000
                socket.connect(InetSocketAddress("10.0.0.1", 53), 5_000)
                DnsTcpFrameCodec.writeFrame(socket.getOutputStream(), blockedQuery())
                val response = requireNotNull(DnsTcpFrameCodec.readFrame(socket.getInputStream()))
                assertEquals("Block policy must return NXDOMAIN", 3, response[3].toInt() and 15)
            }
            Thread.sleep(1_000)
            assertEquals(
                "Background queries must not trigger a diagnostics Flow refresh",
                backgroundSnapshot,
                DnsVpnService.diagnosticsFlow.value
            )

            context.startActivity(
                Intent(context, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)
            )
            val refreshed = withTimeout(5_000) {
                DnsVpnService.diagnosticsFlow.first {
                    it.blocked > backgroundSnapshot.blocked && it.received > backgroundSnapshot.received
                }
            }
            assertTrue(refreshed.terminalCount <= refreshed.received)
            assertTrue("Dashboard did not render resumed totals", waitForDiagnosticsTotals())
        } finally {
            context.startService(
                Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)
            )
            withTimeout(15_000) {
                DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED }
            }
        }
    }

    private fun blockedQuery(): ByteArray =
        (listOf<Byte>(0, 123, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            "doubleclick.net".split('.').flatMap {
                listOf(it.length.toByte()) + it.toByteArray().toList()
            } + listOf<Byte>(0, 0, 1, 0, 1)).toByteArray()

    private fun waitForDiagnosticsCard(): Boolean {
        val deadline = SystemClock.elapsedRealtime() + 5_000
        while (SystemClock.elapsedRealtime() < deadline) {
            if (visibleTexts().any { it == "DNS 診斷" }) return true
            InstrumentationRegistry.getInstrumentation().uiAutomation
                .executeShellCommand("input swipe 500 1600 500 350 250").close()
            Thread.sleep(200)
        }
        return false
    }

    private fun waitForDiagnosticsTotals(): Boolean {
        val deadline = SystemClock.elapsedRealtime() + 5_000
        val pattern = Regex("收到 (\\d+)｜解析 (\\d+)｜攔截 (\\d+)")
        while (SystemClock.elapsedRealtime() < deadline) {
            val snapshot = DnsVpnService.diagnosticsFlow.value
            val matched = visibleTexts().firstNotNullOfOrNull { pattern.find(it) }
            if (matched != null) {
                val (received, resolved, blocked) = matched.destructured
                if (received.toLong() == snapshot.received &&
                    resolved.toLong() == snapshot.resolved &&
                    blocked.toLong() == snapshot.blocked) return true
            }
            InstrumentationRegistry.getInstrumentation().uiAutomation
                .executeShellCommand("input swipe 500 1600 500 350 250").close()
            Thread.sleep(200)
        }
        return false
    }

    private fun visibleTexts(): List<String> {
        val result = mutableListOf<String>()
        fun collect(node: AccessibilityNodeInfo?) {
            if (node == null || result.size >= 100) return
            node.text?.toString()?.let(result::add)
            for (index in 0 until node.childCount) collect(node.getChild(index))
        }
        collect(InstrumentationRegistry.getInstrumentation().uiAutomation.rootInActiveWindow)
        return result
    }
}
