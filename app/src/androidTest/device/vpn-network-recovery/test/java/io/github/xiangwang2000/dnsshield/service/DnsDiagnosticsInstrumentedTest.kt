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
class DnsDiagnosticsInstrumentedTest {
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
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
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
        return scrollToVisibleNode("dns_diagnostics_card", deadline) != null
    }

    private fun waitForDiagnosticsTotals(): Boolean {
        val deadline = SystemClock.elapsedRealtime() + 5_000
        val summaryPattern = Regex("解析 (\\d+) · 攔截 (\\d+) · 失敗 (\\d+)")
        val advancedPattern = Regex("收到 (\\d+) · 拒絕 (\\d+) · 超載 (\\d+)")
        val diagnosticsCard = scrollToVisibleNode("dns_diagnostics_card", deadline) ?: return false
        while (SystemClock.elapsedRealtime() < deadline) {
            val snapshot = DnsVpnService.diagnosticsFlow.value
            val summary = visibleTexts().firstNotNullOfOrNull { summaryPattern.find(it) }
            if (summary != null) {
                val (resolved, blocked, failed) = summary.destructured
                if (resolved.toLong() == snapshot.resolved &&
                    blocked.toLong() == snapshot.blocked &&
                    failed.toLong() == snapshot.failed
                ) {
                    if (!diagnosticsCard.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return false
                    val advancedToggle = scrollToVisibleNode("toggle_advanced_diagnostics", deadline) ?: return false
                    if (!advancedToggle.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return false

                    while (SystemClock.elapsedRealtime() < deadline) {
                        val current = DnsVpnService.diagnosticsFlow.value
                        val advanced = visibleTexts().firstNotNullOfOrNull { advancedPattern.find(it) }
                        if (advanced != null) {
                            val (received, rejected, overloaded) = advanced.destructured
                            if (received.toLong() == current.received &&
                                rejected.toLong() == current.rejected &&
                                overloaded.toLong() == current.overloaded
                            ) return true
                        }
                        scrollDiagnosticsForward()
                        Thread.sleep(150)
                    }
                    return false
                }
            }
            Thread.sleep(200)
        }
        return false
    }

    private fun scrollToVisibleNode(tag: String, deadline: Long): AccessibilityNodeInfo? {
        while (SystemClock.elapsedRealtime() < deadline) {
            val node = findNode(tag)
            if (node?.isVisibleToUser == true) return node
            scrollDiagnosticsForward()
            Thread.sleep(150)
        }
        return null
    }

    private fun scrollDiagnosticsForward() {
        findNode("control_center_list")?.performAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)
    }

    private fun findNode(tag: String): AccessibilityNodeInfo? {
        val root = InstrumentationRegistry.getInstrumentation().uiAutomation.rootInActiveWindow ?: return null
        fun find(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
            if (node.viewIdResourceName == tag) return node.takeIf { it.refresh() }
            for (index in 0 until node.childCount) {
                node.getChild(index)?.let { child -> find(child)?.let { return it } }
            }
            return null
        }
        return find(root)
    }

    private fun visibleTexts(): List<String> {
        val result = mutableListOf<String>()
        fun collect(node: AccessibilityNodeInfo?) {
            if (node == null || result.size >= 100) return
            if (node.isVisibleToUser) node.text?.toString()?.let(result::add)
            for (index in 0 until node.childCount) collect(node.getChild(index))
        }
        collect(InstrumentationRegistry.getInstrumentation().uiAutomation.rootInActiveWindow)
        return result
    }
}
