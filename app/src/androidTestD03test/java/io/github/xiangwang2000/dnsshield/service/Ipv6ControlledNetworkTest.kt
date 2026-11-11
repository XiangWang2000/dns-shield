package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.DnsServer
import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Requires the explicit controlled LAN arguments; ordinary emulator NAT is insufficient. */
@RunWith(AndroidJUnit4::class)
class Ipv6ControlledNetworkTest {
    @Test fun nativeIpv6Dns64Nat64AndBackupResolver() = runBlocking { runScenario(encrypted = false) }
    @Test fun strictDohBackupUsesIpv6BootstrapOverNat64() = runBlocking { runScenario(encrypted = true) }

    @Suppress("DEPRECATION")
    private suspend fun runScenario(encrypted: Boolean) {
        val args = InstrumentationRegistry.getArguments()
        val resolver = args.getString("lab_dns_v6")
        assumeTrue("Requires the controlled IPv6-only LAN", resolver != null)
        val profile = args.getString("lab_profile") ?: "ipv6-only"
        require(profile in setOf("ipv6-only", "ipv6-only-no-clat", "dual-stack"))
        val primary = requireNotNull(args.getString("lab_unavailable_v6"))
        val bootstrap = requireNotNull(args.getString("lab_doh_bootstrap_v6"))
        val synthesized = requireNotNull(args.getString("lab_synthesized_v6"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".d03test"))
        assertNull("Approve the isolated VPN before execution", VpnService.prepare(context))
        val manager = context.getSystemService(ConnectivityManager::class.java)
        // STOPPED marks app cleanup; Android may still be withdrawing the previous VPN.
        fun isValidatedUnderlay(network: Network?): Boolean =
            network?.let(manager::getNetworkCapabilities)?.let { caps ->
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            } == true

        val physical = withTimeout(10_000) {
            var active = manager.activeNetwork
            while (!isValidatedUnderlay(active)) {
                delay(100)
                active = manager.activeNetwork
            }
            requireNotNull(active)
        }
        val properties = requireNotNull(manager.getLinkProperties(physical))
        assertTrue(properties.linkAddresses.any { it.address is Inet6Address && !it.address.isLinkLocalAddress })
        assertTrue(properties.routes.any { it.destination.address is Inet6Address && it.destination.prefixLength == 0 })
        if (profile == "dual-stack") {
            assertTrue("Dual-stack profile requires IPv4 and IPv6", properties.linkAddresses.any { it.address is Inet4Address })
        } else for (network in manager.allNetworks) {
            val caps = manager.getNetworkCapabilities(network) ?: continue
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                assertFalse("IPv4 underlay/fallback is present: ${manager.getLinkProperties(network)}",
                    manager.getLinkProperties(network)!!.linkAddresses.any { it.address is Inet4Address })
            }
        }
        if (profile == "ipv6-only-no-clat") {
            val activeIpv4 = java.util.Collections.list(java.net.NetworkInterface.getNetworkInterfaces())
                .filter { it.isUp }.flatMap { iface ->
                    java.util.Collections.list(iface.inetAddresses).filterIsInstance<Inet4Address>()
                        .filterNot { it.isLoopbackAddress }.map { "${iface.name}=${it.hostAddress}" }
                }
            assertTrue("An active IPv4 interface is present: $activeIpv4", activeIpv4.isEmpty())
        }
        println("CONTROLLED_UNDERLAY profile=$profile network=${physical.networkHandle} properties=$properties")
        val dao = AppDatabase.getDatabase(context).dnsDao()
        val previous = dao.getActiveDnsServer()
        val id = if (encrypted) 92002 else 92001
        val selected = DnsServer(
            id = id, name = "Controlled IPv6 ${if (encrypted) "DoH" else "DNS64"}",
            primaryIp = primary, secondaryIp = resolver, isCustom = true,
            allowPlaintextFallback = !encrypted,
            primaryDohUrl = if (encrypted) "https://[$primary]/dns-query" else null,
            secondaryDohUrl = if (encrypted) "https://dns.google/dns-query" else null,
            secondaryDohBootstrapIps = if (encrypted) bootstrap else null
        )
        try {
            dao.insertDnsServer(selected)
            assertTrue(dao.setActiveDnsServer(id))
            DnsVpnService.setUiForeground(true)
            ContextCompat.startForegroundService(context, Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START))
            withTimeout(30_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING } }
            withTimeout(15_000) { DnsVpnService.underlyingNetworkConnectivityFlow.first { it == UnderlyingNetworkConnectivity.ONLINE } }
            delay(1_000)
            val domain = if (encrypted) "example.com" else "ipv4-only.dns-shield.test"
            for (type in listOf(1, 28)) {
                val wire = query(0x6100 + type, domain, type)
                val response = udp(wire)
                assertAnswer(response, wire)
                if (!encrypted && type == 28) assertTrue(addresses(response).contains(ip(synthesized)))
            }
            val wire = query(0x6200, domain, 28)
            val response = Socket().use { socket ->
                socket.soTimeout = 10_000
                socket.connect(InetSocketAddress(ip(DnsVpnAddresses.IPV6_DNS), 53), 5_000)
                DnsTcpFrameCodec.writeFrame(socket.getOutputStream(), wire)
                requireNotNull(DnsTcpFrameCodec.readFrame(socket.getInputStream()))
            }
            assertAnswer(response, wire)
            if (!encrypted) {
                assertTrue(addresses(response).contains(ip(synthesized)))
                assertTrue(http(synthesized, 18080).contains("DNS_SHIELD_NAT64_IPV4_OK"))
            } else {
                assertTrue("Strict mode did not use DoH", DnsVpnService.dnsTransportStatusFlow.value.contains("DoH"))
                assertFalse(DnsVpnService.dnsTransportStatusFlow.value.contains("明文"))
            }
            assertTrue(http(requireNotNull(resolver), 18081).contains("DNS_SHIELD_NATIVE_IPV6_OK"))
            if (profile == "dual-stack") {
                assertTrue(http("192.0.2.80", 18080).contains("DNS_SHIELD_NAT64_IPV4_OK"))
            } else if (profile == "ipv6-only-no-clat") {
                var ipv4Unavailable = false
                try {
                    Socket().use { it.connect(InetSocketAddress(ip("192.0.2.80"), 18080), 1500) }
                } catch (_: java.io.IOException) { ipv4Unavailable = true }
                assertTrue("An IPv4 socket succeeded despite the no-CLAT profile", ipv4Unavailable)
            }
            assertEquals(VpnLifecycleState.RUNNING, DnsVpnService.lifecycleStateFlow.value)
            assertTrue(manager.allNetworks.contains(physical))
            println("CONTROLLED_IPV6_PASS profile=$profile encrypted=$encrypted primaryUnavailable=$primary backup=$resolver tcp=true")
        } finally {
            try {
                context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
                withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED } }
            } finally {
                DnsVpnService.setUiForeground(false)
                if (previous != null) dao.setActiveDnsServer(previous.id)
                dao.deleteDnsServerById(id)
            }
        }
    }

    private fun ip(value: String): InetAddress = requireNotNull(IpAddressLiteral.parse(value)).toInetAddress()
    private fun query(id: Int, domain: String, type: Int): ByteArray =
        byteArrayOf((id ushr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            domain.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() }.toByteArray() +
            byteArrayOf(0, 0, type.toByte(), 0, 1)

    private fun udp(wire: ByteArray): ByteArray = DatagramSocket().use { socket ->
        socket.soTimeout = 10_000
        socket.connect(ip(DnsVpnAddresses.IPV6_DNS), 53)
        socket.send(DatagramPacket(wire, wire.size))
        val packet = DatagramPacket(ByteArray(4096), 4096)
        socket.receive(packet)
        packet.data.copyOf(packet.length)
    }
    private fun assertAnswer(response: ByteArray, wire: ByteArray) {
        val query = (DnsMessageValidator.parseQuery(wire) as DnsQueryParseResult.Valid).query
        assertTrue(DnsMessageValidator.isValidResponse(response, query))
        assertEquals(0, readUnsignedShort(response, 2) and 0x0F)
        assertTrue(readUnsignedShort(response, 6) > 0)
    }
    private fun addresses(response: ByteArray): List<InetAddress> {
        fun skipName(start: Int): Int {
            var offset = start
            while (true) {
                val length = response[offset].toInt() and 255
                if (length and 0xC0 == 0xC0) return offset + 2
                if (length == 0) return offset + 1
                offset += length + 1
            }
        }
        var offset = skipName(12) + 4
        val result = mutableListOf<InetAddress>()
        repeat(readUnsignedShort(response, 6)) {
            offset = skipName(offset)
            val type = readUnsignedShort(response, offset)
            val length = readUnsignedShort(response, offset + 8)
            offset += 10
            if ((type == 1 && length == 4) || (type == 28 && length == 16)) {
                result += InetAddress.getByAddress(response.copyOfRange(offset, offset + length))
            }
            offset += length
        }
        return result
    }
    private fun http(address: String, port: Int): String = Socket().use { socket ->
        socket.soTimeout = 10_000
        socket.connect(InetSocketAddress(ip(address), port), 5_000)
        socket.getOutputStream().write("GET / HTTP/1.0\r\nHost: dns-shield.test\r\n\r\n".toByteArray())
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        while (true) {
            val count = socket.getInputStream().read(buffer)
            if (count < 0) break
            output.write(buffer, 0, count)
            check(output.size() <= 4096)
        }
        output.toString("UTF-8")
    }
}
