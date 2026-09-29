package io.github.xiangwang2000.dnsshield.service

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.DnsServer
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
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
class DnsUpstreamTcpTunInstrumentedTest {
    @Test
    fun udpTruncationRetriesUpstreamTcpAndCachesFullAnswer() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".d08test"))
        assertEquals(15353, BuildConfig.DNS_UPSTREAM_PORT)
        assertNull("Approve VPN consent for .d08test before this run", VpnService.prepare(context))

        val dao = AppDatabase.getDatabase(context).dnsDao()
        val previous = dao.getActiveDnsServer()
        val resolverName = "D10 TCP ${UUID.randomUUID()}"
        val domain = "d10-${UUID.randomUUID().toString().replace("-", "")}.example.test"
        val address = InetAddress.getByName("127.0.0.2")
        val udp = DatagramSocket(null).apply {
            bind(InetSocketAddress(address, BuildConfig.DNS_UPSTREAM_PORT))
        }
        val tcp = ServerSocket().apply {
            bind(InetSocketAddress(address, BuildConfig.DNS_UPSTREAM_PORT))
        }
        val udpCount = AtomicInteger()
        val tcpCount = AtomicInteger()
        val fixtureFailure = AtomicReference<Throwable?>()
        val udpThread = Thread {
            try {
                while (!udp.isClosed) {
                    val packet = DatagramPacket(ByteArray(4096), 4096)
                    udp.receive(packet)
                    val request = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    val parsed = (DnsMessageValidator.parseQuery(request) as DnsQueryParseResult.Valid).query
                    val response = DnsMessageValidator.buildServFailResponse(parsed)
                    if (parsed.question.domainName == domain) {
                        udpCount.incrementAndGet()
                        response[2] = 0x83.toByte()
                        response[3] = 0x80.toByte()
                    }
                    udp.send(DatagramPacket(response, response.size, packet.socketAddress))
                }
            } catch (error: Throwable) {
                if (!udp.isClosed) fixtureFailure.set(error)
            }
        }.apply { name = "d10-fake-udp"; isDaemon = true }
        val tcpThread = Thread {
            try {
                tcp.accept().use { socket ->
                    socket.soTimeout = 8_000
                    val input = DataInputStream(socket.getInputStream())
                    val request = ByteArray(input.readUnsignedShort())
                    input.readFully(request)
                    val parsed = (DnsMessageValidator.parseQuery(request) as DnsQueryParseResult.Valid).query
                    assertEquals(domain, parsed.question.domainName)
                    tcpCount.incrementAndGet()
                    val header = DnsMessageValidator.buildServFailResponse(parsed).also {
                        it[2] = 0x81.toByte()
                        it[3] = 0x80.toByte()
                        it[6] = 0
                        it[7] = 18
                    }
                    val record = byteArrayOf(
                        0xc0.toByte(), 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 201.toByte(), 200.toByte()
                    ) + ByteArray(200) { 65 }
                    val fullResponse = header + ByteArrayOutputStream().apply {
                        repeat(18) { write(record) }
                    }.toByteArray()
                    assertTrue(fullResponse.size in 513..DnsMessageValidator.MAX_DNS_MESSAGE_BYTES)
                    val frame = byteArrayOf(
                        (fullResponse.size ushr 8).toByte(), fullResponse.size.toByte()
                    ) + fullResponse
                    val output = socket.getOutputStream()
                    output.write(frame, 0, 7)
                    Thread.sleep(20)
                    output.write(frame, 7, frame.size - 7)
                    output.flush()
                }
            } catch (error: Throwable) {
                if (!tcp.isClosed) fixtureFailure.set(error)
            }
        }.apply { name = "d10-fake-tcp"; isDaemon = true }

        var resolverId: Int? = null
        var started = false
        try {
            dao.insertDnsServer(DnsServer(
                name = resolverName,
                primaryIp = "127.0.0.2",
                secondaryIp = null,
                isCustom = true,
                isActive = false,
                allowPlaintextFallback = true
            ))
            resolverId = dao.getDnsServersList().first { it.name == resolverName }.id
            assertTrue(dao.setActiveDnsServer(requireNotNull(resolverId)))
            udpThread.start()
            tcpThread.start()
            ContextCompat.startForegroundService(
                context, Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
            )
            started = true
            withTimeout(30_000) {
                DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING }
            }
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            withTimeout(10_000) {
                while (connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != true) {
                    delay(50)
                }
            }

            // D09 debounces the initial underlay callbacks before steady-state TCP fallback.
            delay(1_000)
            val firstQuery = dnsQuery(domain, 41)
            val first = sendThroughTun(firstQuery)
            val firstParsed = (DnsMessageValidator.parseQuery(firstQuery) as DnsQueryParseResult.Valid).query
            assertEquals(41, first[1].toInt() and 255)
            assertTrue("Client UDP reply exceeded the no-EDNS 512-byte limit", first.size <= 512)
            assertTrue("Large upstream answer must set TC for the client", first[2].toInt() and 2 != 0)
            assertTrue(DnsMessageValidator.isValidResponse(first, firstParsed))
            assertEquals("Upstream UDP TC was not received once", 1, udpCount.get())
            assertEquals("Upstream TCP retry was not completed once", 1, tcpCount.get())

            val secondQuery = dnsQuery(domain, 42)
            val second = sendThroughTun(secondQuery)
            val secondParsed = (DnsMessageValidator.parseQuery(secondQuery) as DnsQueryParseResult.Valid).query
            assertEquals(42, second[1].toInt() and 255)
            assertTrue(second.size <= 512)
            assertTrue(second[2].toInt() and 2 != 0)
            assertTrue(DnsMessageValidator.isValidResponse(second, secondParsed))
            assertEquals("The truncated upstream UDP reply must not be cached", 1, udpCount.get())
            assertEquals("The full upstream TCP reply was not cached", 1, tcpCount.get())
            assertNull("Fake upstream failed", fixtureFailure.get())
        } finally {
            if (started) {
                context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
                withTimeout(15_000) {
                    DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED }
                }
            }
            previous?.let { dao.setActiveDnsServer(it.id) }
            resolverId?.let { dao.deleteDnsServerById(it) }
            udp.close()
            tcp.close()
            udpThread.join(1_000)
            tcpThread.join(1_000)
            assertFalse(udpThread.isAlive)
            assertFalse(tcpThread.isAlive)
        }
    }

    private fun dnsQuery(domain: String, transactionId: Int): ByteArray =
        ByteArrayOutputStream().also { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeShort(transactionId)
                output.writeShort(0x0100)
                output.writeShort(1)
                repeat(3) { output.writeShort(0) }
                domain.split('.').forEach { label ->
                    output.writeByte(label.length)
                    output.write(label.toByteArray(Charsets.US_ASCII))
                }
                output.writeByte(0)
                output.writeShort(16)
                output.writeShort(1)
            }
        }.toByteArray()

    private fun sendThroughTun(query: ByteArray): ByteArray = DatagramSocket().use { client ->
        client.soTimeout = 500
        client.connect(InetAddress.getByName(DnsVpnService.DUMMY_DNS_IP), 53)
        val deadline = System.nanoTime() + 10_000_000_000L
        while (true) {
            client.send(DatagramPacket(query, query.size))
            val packet = DatagramPacket(ByteArray(4096), 4096)
            try {
                client.receive(packet)
                return@use packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
            } catch (error: SocketTimeoutException) {
                if (System.nanoTime() >= deadline) throw AssertionError("TUN query timed out", error)
            } catch (error: SocketException) {
                throw AssertionError("VPN TUN socket closed during query", error)
            }
        }
        error("unreachable")
    }
}
