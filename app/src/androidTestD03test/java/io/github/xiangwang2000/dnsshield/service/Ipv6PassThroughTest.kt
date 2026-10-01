package io.github.xiangwang2000.dnsshield.service

import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Explicitly dual-stack acceptance; this does not claim IPv6-only/NAT64 coverage. */
@RunWith(AndroidJUnit4::class)
class Ipv6PassThroughTest {
    @Test fun dualStackVpnOffOnOff() = runOffOnOff(includeIpv6 = true)
    @Test fun ipv4OnlyVpnOffOnOff() = runOffOnOff(includeIpv6 = false)

    private fun runOffOnOff(includeIpv6: Boolean) = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".d03test"))
        assertNull("Approve isolated test VPN before execution", VpnService.prepare(context))
        fun command(action: String) = ContextCompat.startForegroundService(context,
            Intent(context, DnsVpnService::class.java).setAction(action))
        suspend fun stopped() {
            if (DnsVpnService.lifecycleStateFlow.value != VpnLifecycleState.STOPPED) {
                context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
                withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED } }
                delay(300)
            }
        }
        stopped()
        probe("before", includeIpv6)
        try {
            command(DnsVpnService.ACTION_START)
            withTimeout(30_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING } }
            probe("vpn-on", includeIpv6)
            query("10.0.0.1", 28)
            println("D03 virtual IPv4 DNS AAAA response: PASS")
        } finally { stopped() }
        probe("after", includeIpv6)
    }

    private fun probe(phase: String, includeIpv6: Boolean) {
        val addresses = if (includeIpv6) listOf("1.1.1.1", "2606:4700:4700::1111") else listOf("1.1.1.1")
        for (address in addresses) {
            retry {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(InetAddress.getByName(address), 443), 5_000)
                    assertTrue(socket.isConnected)
                }
            }
            query(address, 28)
        }
        println("D03 $phase ${if (includeIpv6) "IPv4/IPv6" else "IPv4-only"} TCP connect and UDP DNS AAAA: PASS")
    }

    private fun query(address: String, type: Int) = retry {
        val labels = "example.com".split('.')
        val query = (listOf<Byte>(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            labels.flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } +
            listOf<Byte>(0, 0, type.toByte(), 0, 1)).toByteArray()
        DatagramSocket().use { socket ->
            socket.soTimeout = 8_000
            socket.connect(InetAddress.getByName(address), 53)
            socket.send(DatagramPacket(query, query.size))
            val response = DatagramPacket(ByteArray(4096), 4096)
            socket.receive(response)
            assertTrue(response.length >= 12)
            assertEquals(0x12, response.data[0].toInt() and 255)
            assertEquals(0x34, response.data[1].toInt() and 255)
            assertEquals(0, response.data[3].toInt() and 15)
            assertTrue("Expected AAAA answer", (response.data[6].toInt() and 255) +
                (response.data[7].toInt() and 255) > 0)
        }
    }

    private fun retry(block: () -> Unit) {
        var failure: Exception? = null
        repeat(3) {
            try { block(); return } catch (exception: java.io.IOException) { failure = exception }
        }
        throw requireNotNull(failure)
    }
}
