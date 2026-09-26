package io.github.xiangwang2000.dnsshield.service

import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.net.Socket
import java.net.InetSocketAddress
import java.net.SocketException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DnsTcpTunTest {
    @Test fun tcpThroughRealTunMultipleFramesHalfCloseAndStop() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".d04test"))
        assertNull(VpnService.prepare(context))
        ContextCompat.startForegroundService(context,
            Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START))
        withTimeout(30_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING } }
        try {
            Socket().use { socket ->
                socket.soTimeout = 10_000
                socket.connect(InetSocketAddress("10.0.0.1", 53), 5_000)
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                repeat(3) { index ->
                    val query = query(index + 1)
                    DnsTcpFrameCodec.writeFrame(output, query)
                    val response = requireNotNull(DnsTcpFrameCodec.readFrame(input))
                    assertEquals(index + 1, response[1].toInt() and 255)
                    assertEquals("Shared block policy must return NXDOMAIN", 3, response[3].toInt() and 15)
                }
                DnsTcpFrameCodec.writeFrame(output, query(4))
                socket.shutdownOutput()
                val response = requireNotNull(DnsTcpFrameCodec.readFrame(input))
                assertEquals(4, response[1].toInt() and 255)
                assertEquals(3, response[3].toInt() and 15)
                assertNull(DnsTcpFrameCodec.readFrame(input))
            }
            Socket().use { pending ->
                pending.soTimeout = 10_000
                pending.connect(InetSocketAddress("10.0.0.1", 53), 5_000)
                context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
                withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED } }
                try { assertEquals(-1, pending.getInputStream().read()) }
                catch (_: SocketException) { /* Reset on TUN teardown is valid. */ }
            }
        } finally {
            context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
            withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED } }
        }
    }

    @Test fun udpTruncationClientTcpRetryAndSharedCache(): Unit = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".d04test"))
        assertNull(VpnService.prepare(context))
        val dao = io.github.xiangwang2000.dnsshield.data.AppDatabase.getDatabase(context).dnsDao()
        val previous = dao.getActiveDnsServer()
        val resolverId = 91001
        val address = java.net.InetAddress.getByName("127.0.0.2")
        val udp = java.net.DatagramSocket(null).apply { bind(InetSocketAddress(address, io.github.xiangwang2000.dnsshield.BuildConfig.DNS_TEST_UPSTREAM_PORT)) }
        val tcp = java.net.ServerSocket().apply { bind(InetSocketAddress(address, io.github.xiangwang2000.dnsshield.BuildConfig.DNS_TEST_UPSTREAM_PORT)) }
        val udpCount = java.util.concurrent.atomic.AtomicInteger()
        val tcpCount = java.util.concurrent.atomic.AtomicInteger()
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val udpThread = Thread {
            try {
                val packet = java.net.DatagramPacket(ByteArray(4096), 4096)
                while (!udp.isClosed) {
                    packet.length = packet.data.size
                    udp.receive(packet)
                    val request = packet.data.copyOf(packet.length)
                    val parsed = (DnsMessageValidator.parseQuery(request) as DnsQueryParseResult.Valid).query
                    val response = DnsMessageValidator.buildServFailResponse(parsed)
                    if (parsed.question.domainName == "d11-large.example.test") {
                        udpCount.incrementAndGet()
                        response[2] = 0x83.toByte(); response[3] = 0x80.toByte()
                    }
                    udp.send(java.net.DatagramPacket(response, response.size, packet.socketAddress))
                }
            } catch (error: Throwable) { if (!udp.isClosed) failure.set(error) }
        }.apply { start() }
        val tcpThread = Thread {
            try {
                tcp.accept().use { socket ->
                    socket.soTimeout = 8000
                    val request = requireNotNull(DnsTcpFrameCodec.readFrame(socket.getInputStream()))
                    tcpCount.incrementAndGet()
                    val parsed = (DnsMessageValidator.parseQuery(request) as DnsQueryParseResult.Valid).query
                    val response = DnsMessageValidator.buildServFailResponse(parsed).also {
                        it[2] = 0x81.toByte(); it[3] = 0x80.toByte(); it[7] = 10
                    }
                    val record = byteArrayOf(0xc0.toByte(), 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 201.toByte(), 200.toByte()) + ByteArray(200) { 65 }
                    DnsTcpFrameCodec.writeFrame(socket.getOutputStream(), response + (1..10).flatMap { record.toList() }.toByteArray())
                }
            } catch (error: Throwable) { if (!tcp.isClosed) failure.set(error) }
        }.apply { start() }
        try {
            dao.insertDnsServer(io.github.xiangwang2000.dnsshield.data.DnsServer(
                id = resolverId, name = "D11 loopback", primaryIp = "127.0.0.2", secondaryIp = null,
                isCustom = true, allowPlaintextFallback = true))
            assertTrue(dao.setActiveDnsServer(resolverId))
            ContextCompat.startForegroundService(context,
                Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START))
            withTimeout(30_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING } }
            val connectivity = context.getSystemService(android.net.ConnectivityManager::class.java)
            withTimeout(10_000) {
                while (connectivity.getNetworkCapabilities(connectivity.activeNetwork)
                        ?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) != true) {
                    kotlinx.coroutines.delay(25)
                }
            }
            val request = (listOf<Byte>(0, 41, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
                "d11-large.example.test".split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } +
                listOf<Byte>(0, 0, 16, 0, 1)).toByteArray()
            java.net.DatagramSocket().use { client ->
                client.soTimeout = 500
                client.connect(java.net.InetAddress.getByName("10.0.0.1"), 53)
                val answer = java.net.DatagramPacket(ByteArray(4096), 4096)
                val until = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10)
                while (true) {
                    client.send(java.net.DatagramPacket(request, request.size))
                    try {
                        client.receive(answer)
                        break
                    } catch (error: java.net.SocketTimeoutException) {
                        if (System.nanoTime() >= until) throw AssertionError(
                            "UDP timeout: upstream UDP=${udpCount.get()}, TCP=${tcpCount.get()}, fixture=${failure.get()}", error)
                    }
                }
                assertTrue(answer.length <= 512)
                assertTrue("UDP response must request TCP retry", answer.data[2].toInt() and 2 != 0)
            }
            Socket().use { client ->
                client.soTimeout = 10_000
                client.connect(InetSocketAddress("10.0.0.1", 53), 5_000)
                repeat(2) { index ->
                    val next = request.copyOf().also { it[1] = (42 + index).toByte() }
                    DnsTcpFrameCodec.writeFrame(client.getOutputStream(), next)
                    val answer = requireNotNull(DnsTcpFrameCodec.readFrame(client.getInputStream()))
                    assertTrue("TCP must retain the complete large response: bytes=${answer.size}, flags=${answer[2]}, rcode=${answer[3]}, UDP=${udpCount.get()}, TCP=${tcpCount.get()}, fixture=${failure.get()}", answer.size > 2000)
                    assertEquals(0, answer[2].toInt() and 2)
                    assertEquals(42 + index, answer[1].toInt() and 255)
                    assertTrue(DnsMessageValidator.isValidResponse(answer,
                        (DnsMessageValidator.parseQuery(next) as DnsQueryParseResult.Valid).query))
                }
            }
            assertEquals(1, udpCount.get())
            assertEquals("UDP/TCP client retries must share the full response cache", 1, tcpCount.get())
            failure.get()?.let { throw AssertionError("Fake upstream failed", it) }
        } finally {
            context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
            withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED } }
            if (previous != null) dao.setActiveDnsServer(previous.id)
            dao.deleteDnsServerById(resolverId)
            udp.close(); tcp.close(); udpThread.join(1000); tcpThread.join(9000)
            assertFalse(udpThread.isAlive); assertFalse(tcpThread.isAlive)
        }
    }

    private fun query(id: Int): ByteArray = (listOf<Byte>(0, id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
        "doubleclick.net".split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } +
        listOf<Byte>(0, 0, 1, 0, 1)).toByteArray()
}
