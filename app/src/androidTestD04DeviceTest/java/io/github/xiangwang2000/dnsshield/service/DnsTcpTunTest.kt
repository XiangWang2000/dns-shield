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
            Socket().use { socket ->
                socket.soTimeout = 10_000
                socket.connect(InetSocketAddress(java.net.InetAddress.getByName(DnsVpnAddresses.IPV6_DNS), 53), 5_000)
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                repeat(3) { index ->
                    val query = query(11 + index)
                    DnsTcpFrameCodec.writeFrame(output, query)
                    val response = requireNotNull(DnsTcpFrameCodec.readFrame(input))
                    assertEquals(11 + index, response[1].toInt() and 255)
                    assertEquals(3, response[3].toInt() and 15)
                }
                DnsTcpFrameCodec.writeFrame(output, query(14))
                socket.shutdownOutput()
                val response = requireNotNull(DnsTcpFrameCodec.readFrame(input))
                assertEquals(14, response[1].toInt() and 255)
                assertEquals(3, response[3].toInt() and 15)
                assertNull(DnsTcpFrameCodec.readFrame(input))
            }
            Socket().use { pendingIpv4 ->
                pendingIpv4.soTimeout = 10_000
                pendingIpv4.connect(InetSocketAddress("10.0.0.1", 53), 5_000)
                Socket().use { pendingIpv6 ->
                    pendingIpv6.soTimeout = 10_000
                    pendingIpv6.connect(InetSocketAddress(java.net.InetAddress.getByName(DnsVpnAddresses.IPV6_DNS), 53), 5_000)
                    context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
                    withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED } }
                    try { assertEquals(-1, pendingIpv4.getInputStream().read()) }
                    catch (_:SocketException) { /* Reset on TUN teardown is valid. */ }
                    try { assertEquals(-1, pendingIpv6.getInputStream().read()) }
                    catch (_:SocketException) { /* Reset on TUN teardown is valid. */ }
                }
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
        val udp = java.net.DatagramSocket(null).apply { bind(InetSocketAddress(address, io.github.xiangwang2000.dnsshield.BuildConfig.DNS_UPSTREAM_PORT)) }
        val tcp = java.net.ServerSocket().apply { bind(InetSocketAddress(address, io.github.xiangwang2000.dnsshield.BuildConfig.DNS_UPSTREAM_PORT)) }
        val udpCount = java.util.concurrent.atomic.AtomicInteger()
        val tcpCount = java.util.concurrent.atomic.AtomicInteger()
        val addressCount = java.util.concurrent.atomic.AtomicInteger()
        val blockedCount = java.util.concurrent.atomic.AtomicInteger()
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val udpThread = Thread {
            try {
                val packet = java.net.DatagramPacket(ByteArray(4096), 4096)
                while (!udp.isClosed) {
                    packet.length = packet.data.size
                    udp.receive(packet)
                    val request = packet.data.copyOf(packet.length)
                    val parsed = (DnsMessageValidator.parseQuery(request) as DnsQueryParseResult.Valid).query
                    val response = when (parsed.question.domainName) {
                        "d11-large.example.test", "d11-large-ipv6.example.test" -> {
                            udpCount.incrementAndGet()
                            largeTxtResponse(parsed, recordCount = 4, truncated = true).also {
                                check(it.size > 512) { "TC upstream fixture response must exceed the client UDP limit" }
                            }
                        }
                        "ipv6-a.example.test", "ipv6-aaaa.example.test" -> {
                            addressCount.incrementAndGet()
                            addressResponse(parsed)
                        }
                        "doubleclick.net" -> {
                            blockedCount.incrementAndGet()
                            DnsMessageValidator.buildServFailResponse(parsed)
                        }
                        else -> DnsMessageValidator.buildServFailResponse(parsed)
                    }
                    udp.send(java.net.DatagramPacket(response, response.size, packet.socketAddress))
                }
            } catch (error: Throwable) { if (!udp.isClosed) failure.set(error) }
        }.apply { start() }
        val tcpThread = Thread {
            try {
                repeat(2) {
                    tcp.accept().use { socket ->
                        socket.soTimeout = 8000
                        val request = requireNotNull(DnsTcpFrameCodec.readFrame(socket.getInputStream()))
                        tcpCount.incrementAndGet()
                        val parsed = (DnsMessageValidator.parseQuery(request) as DnsQueryParseResult.Valid).query
                        DnsTcpFrameCodec.writeFrame(socket.getOutputStream(), largeTxtResponse(parsed, recordCount = 30))
                    }
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
            // Let initial underlying-network callbacks finish before testing steady-state TCP fallback.
            kotlinx.coroutines.delay(1_000)
            listOf("ipv6-a.example.test" to 1, "ipv6-aaaa.example.test" to 28).forEachIndexed { index, (domain, type) ->
                val udpWire = query(0x5200 + index, domain, type)
                val parsedUdp = parseQuery(udpWire)
                assertDnsAddressAnswer(udpQuery(DnsVpnAddresses.IPV6_DNS, udpWire), parsedUdp, type)

                val tcpWire = query(0x5210 + index, domain, type)
                val parsedTcp = parseQuery(tcpWire)
                assertDnsAddressAnswer(tcpQuery(DnsVpnAddresses.IPV6_DNS, tcpWire), parsedTcp, type)
            }
            assertEquals("IPv6 UDP A and AAAA queries should each reach upstream once; TCP reads the cache", 2, addressCount.get())

            if (InstrumentationRegistry.getArguments().getString("exercise_ip_change") == "true") {
                assertSelectedIpChangeInvalidatesCache(context, addressCount)
            }

            val blockedWire = query(0x5220, "doubleclick.net", 1)
            val blockedQuery = parseQuery(blockedWire)
            val blockedAnswer = udpQuery(DnsVpnAddresses.IPV6_DNS, blockedWire)
            assertTrue(DnsMessageValidator.isValidResponse(blockedAnswer, blockedQuery))
            assertEquals(3, readUnsignedShort(blockedAnswer, 2) and 0x0F)
            assertEquals("Blocked IPv6 query must not reach upstream", 0, blockedCount.get())

            val request = query(41, "d11-large.example.test", 16)
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
                    assertTrue("TCP must retain the complete large response: bytes=${answer.size}, flags=${answer[2]}, rcode=${answer[3]}, UDP=${udpCount.get()}, TCP=${tcpCount.get()}, fixture=${failure.get()}", answer.size > 4096)
                    assertEquals(0, answer[2].toInt() and 2)
                    assertEquals(30, ((answer[6].toInt() and 255) shl 8) or (answer[7].toInt() and 255))
                    assertEquals(42 + index, answer[1].toInt() and 255)
                    assertTrue(DnsMessageValidator.isValidResponse(answer,
                        (DnsMessageValidator.parseQuery(next) as DnsQueryParseResult.Valid).query))
                }
            }
            assertEquals(1, udpCount.get())
            assertEquals("UDP/TCP client retries must share the full response cache", 1, tcpCount.get())

            val ipv6Request = query(0x5230, "d11-large-ipv6.example.test", 16)
            val ipv6Parsed = parseQuery(ipv6Request)
            val ipv6UdpAnswer = udpQuery(DnsVpnAddresses.IPV6_DNS, ipv6Request)
            assertTrue("IPv6 UDP should receive a small TC response", ipv6UdpAnswer.size <= 512)
            assertTrue("IPv6 UDP response must request TCP retry", DnsMessageValidator.isTruncatedResponse(ipv6UdpAnswer, ipv6Parsed))
            Socket().use { client ->
                client.soTimeout = 10_000
                client.connect(InetSocketAddress(java.net.InetAddress.getByName(DnsVpnAddresses.IPV6_DNS), 53), 5_000)
                repeat(2) { index ->
                    val next = query(0x5240 + index, "d11-large-ipv6.example.test", 16)
                    val parsed = parseQuery(next)
                    DnsTcpFrameCodec.writeFrame(client.getOutputStream(), next)
                    val answer = requireNotNull(DnsTcpFrameCodec.readFrame(client.getInputStream()))
                    assertTrue("IPv6 TCP must retain the complete large answer: ${answer.size} bytes", answer.size > 4096)
                    assertEquals(0, readUnsignedShort(answer, 2) and 0x0200)
                    assertEquals(30, readUnsignedShort(answer, 6))
                    assertTrue(DnsMessageValidator.isValidResponse(answer, parsed))
                }
            }
            assertEquals(2, udpCount.get())
            assertEquals("IPv4 and IPv6 retries should each fetch one full answer from upstream", 2, tcpCount.get())
            failure.get()?.let { throw AssertionError("Fake upstream failed", it) }
        } finally {
            try {
                context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
                withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED } }
                if (previous != null) dao.setActiveDnsServer(previous.id)
                dao.deleteDnsServerById(resolverId)
            } finally {
                udp.close(); tcp.close(); udpThread.join(1000); tcpThread.join(9000)
                assertFalse(udpThread.isAlive); assertFalse(tcpThread.isAlive)
            }
        }
    }

    /** Only the explicitly requested emulator run changes its disposable underlay address. */
    @Suppress("DEPRECATION")
    private suspend fun assertSelectedIpChangeInvalidatesCache(
        context: android.content.Context,
        upstreamCount: java.util.concurrent.atomic.AtomicInteger
    ) {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        fun shell(command: String): String = android.os.ParcelFileDescriptor.AutoCloseInputStream(
            automation.executeShellCommand(command)
        ).bufferedReader().use { it.readText() }
        assertEquals("This scenario is limited to the disposable Android emulator", "1", shell("getprop ro.kernel.qemu").trim())
        val manager = context.getSystemService(android.net.ConnectivityManager::class.java)
        val physical = manager.allNetworks.first { network ->
            manager.getNetworkCapabilities(network)?.let {
                !it.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) &&
                    it.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) &&
                    it.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            } == true
        }
        val networkId = physical.networkHandle
        val iface = requireNotNull(manager.getLinkProperties(physical)?.interfaceName)
        require(iface.matches(Regex("[a-zA-Z0-9_.-]+")))
        val cidr = "2001:db8:7c0d::2/64"
        val address = requireNotNull(IpAddressLiteral.parse("2001:db8:7c0d::2")).toInetAddress()
        assertFalse(manager.getLinkProperties(physical)!!.linkAddresses.any { it.address == address })
        val oldClient = DnsVpnService.getOkHttpClient()
        var added = false
        var verified = false
        try {
            assertEquals("", shell("su 0 ip -6 addr add $cidr dev $iface nodad").trim())
            added = true
            val observed = kotlinx.coroutines.withTimeoutOrNull(10_000) {
                while (manager.getLinkProperties(physical)?.linkAddresses?.any { it.address == address } != true ||
                    DnsVpnService.getOkHttpClient() === oldClient) kotlinx.coroutines.delay(50)
                true
            } == true
            assertTrue("IP change did not rebuild DoH: network=$networkId properties=${manager.getLinkProperties(physical)} clientChanged=${DnsVpnService.getOkHttpClient() !== oldClient}", observed)
            kotlinx.coroutines.delay(1_000)
            assertEquals(networkId, physical.networkHandle)
            assertTrue("The same physical Network must remain connected", manager.allNetworks.contains(physical))
            assertTrue(manager.getNetworkCapabilities(physical)
                ?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true)
            val countBefore = upstreamCount.get()
            val wire = query(0x5260, "ipv6-a.example.test", 1)
            assertDnsAddressAnswer(udpQuery(DnsVpnAddresses.IPV6_DNS, wire), parseQuery(wire), 1)
            assertEquals("Same-ID IP changes must invalidate the previously cached answer", countBefore + 1, upstreamCount.get())
            verified = true
            println("IP_CONTEXT_CHANGE_PASS networkId=$networkId interface=$iface cacheInvalidated=true dohClientRebuilt=true")
        } finally {
            if (added) {
                val clientBeforeRemoval = DnsVpnService.getOkHttpClient()
                assertEquals("", shell("su 0 ip -6 addr del $cidr dev $iface").trim())
                val restored = kotlinx.coroutines.withTimeoutOrNull(10_000) {
                    while (manager.getLinkProperties(physical)?.linkAddresses?.any { it.address == address } == true ||
                        DnsVpnService.getOkHttpClient() === clientBeforeRemoval) kotlinx.coroutines.delay(50)
                    true
                } == true
                if (verified) assertTrue("Removing the test address must restore IP context and rebuild DoH", restored)
            }
        }
    }

    @Test fun idleTcpSessionClosesAndNextConnectionStillWorks() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".d04test"))
        assertNull(VpnService.prepare(context))
        ContextCompat.startForegroundService(context,
            Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START))
        withTimeout(30_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING } }
        try {
            Socket().use { idle ->
                idle.soTimeout = 15_000
                idle.connect(InetSocketAddress("10.0.0.1", 53), 5_000)
                val started = System.nanoTime()
                try { assertEquals(-1, idle.getInputStream().read()) }
                catch (_: SocketException) { /* A TCP reset also closes the idle session. */ }
                assertTrue("Idle session closed before its timeout",
                    System.nanoTime() - started >= java.util.concurrent.TimeUnit.SECONDS.toNanos(5))
            }
            Socket().use { active ->
                active.soTimeout = 10_000
                active.connect(InetSocketAddress("10.0.0.1", 53), 5_000)
                DnsTcpFrameCodec.writeFrame(active.getOutputStream(), query(71))
                val answer = requireNotNull(DnsTcpFrameCodec.readFrame(active.getInputStream()))
                assertEquals(71, answer[1].toInt() and 255)
                assertEquals(3, answer[3].toInt() and 15)
            }
        } finally {
            context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
            withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED } }
        }
    }

    @Test fun exhaustedTcpSessionsKeepThe32ndClientAndBoundOverflow() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".d04test"))
        assertNull(VpnService.prepare(context))
        ContextCompat.startForegroundService(context,
            Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START))
        withTimeout(30_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING } }
        val held = mutableListOf<Socket>()
        try {
            repeat(32) {
                held += Socket().apply {
                    soTimeout = 3_000
                    connect(InetSocketAddress("10.0.0.1", 53), 2_000)
                }
            }
            DnsTcpFrameCodec.writeFrame(held.first().getOutputStream(), query(72))
            val first = requireNotNull(DnsTcpFrameCodec.readFrame(held.first().getInputStream()))
            assertEquals(3, first[3].toInt() and 15)
            Socket().use { excess ->
                excess.soTimeout = 2_000
                val overflowAnswered = try {
                    excess.connect(InetSocketAddress("10.0.0.1", 53), 1_000)
                    DnsTcpFrameCodec.writeFrame(excess.getOutputStream(), query(73))
                    DnsTcpFrameCodec.readFrame(excess.getInputStream()) != null
                } catch (_: java.io.IOException) {
                    false
                }
                if (overflowAnswered) {
                    val oldestClosed = try {
                        DnsTcpFrameCodec.writeFrame(held[1].getOutputStream(), query(75))
                        DnsTcpFrameCodec.readFrame(held[1].getInputStream()) == null
                    } catch (_: java.io.IOException) {
                        true
                    }
                    assertTrue("Overflow was admitted without evicting an older session", oldestClosed)
                }
            }
            DnsTcpFrameCodec.writeFrame(held.first().getOutputStream(), query(74))
            val surviving = requireNotNull(DnsTcpFrameCodec.readFrame(held.first().getInputStream()))
            assertEquals(74, surviving[1].toInt() and 255)
            assertEquals(3, surviving[3].toInt() and 15)
        } finally {
            held.forEach { it.close() }
            context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
            withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED } }
        }
    }
    private fun query(id: Int, domain: String = "doubleclick.net", type: Int = 1): ByteArray =
        (listOf<Byte>((id ushr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            domain.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } +
            listOf<Byte>(0, (type ushr 8).toByte(), type.toByte(), 0, 1)).toByteArray()

    private fun parseQuery(wire: ByteArray): ParsedDnsQuery =
        (DnsMessageValidator.parseQuery(wire) as DnsQueryParseResult.Valid).query

    private fun udpQuery(address: String, wire: ByteArray): ByteArray =
        java.net.DatagramSocket().use { socket ->
            socket.soTimeout = 8_000
            socket.connect(java.net.InetAddress.getByName(address), 53)
            socket.send(java.net.DatagramPacket(wire, wire.size))
            val packet = java.net.DatagramPacket(ByteArray(4096), 4096)
            socket.receive(packet)
            packet.data.copyOf(packet.length)
        }

    private fun tcpQuery(address: String, wire: ByteArray): ByteArray = Socket().use { socket ->
        socket.soTimeout = 8_000
        socket.connect(InetSocketAddress(java.net.InetAddress.getByName(address), 53), 5_000)
        DnsTcpFrameCodec.writeFrame(socket.getOutputStream(), wire)
        requireNotNull(DnsTcpFrameCodec.readFrame(socket.getInputStream()))
    }

    private fun addressResponse(query: ParsedDnsQuery): ByteArray {
        val type = query.question.type
        val address = when (type) {
            1 -> byteArrayOf(203.toByte(), 0, 113, 7)
            28 -> byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte()) + ByteArray(10) + byteArrayOf(0, 7)
            else -> return DnsMessageValidator.buildServFailResponse(query)
        }
        val response = query.wire.copyOf().also {
            it[2] = 0x81.toByte()
            it[3] = 0x80.toByte()
            it[6] = 0
            it[7] = 1
        }
        val record = byteArrayOf(
            0xc0.toByte(), 12, (type ushr 8).toByte(), type.toByte(), 0, 1,
            0, 0, 0, 60, (address.size ushr 8).toByte(), address.size.toByte()
        )
        return response + record + address
    }

    private fun largeTxtResponse(
        query: ParsedDnsQuery,
        recordCount: Int,
        truncated: Boolean = false
    ): ByteArray {
        val response = DnsMessageValidator.buildServFailResponse(query).also {
            it[2] = if (truncated) 0x83.toByte() else 0x81.toByte()
            it[3] = 0x80.toByte()
            it[6] = (recordCount ushr 8).toByte()
            it[7] = recordCount.toByte()
        }
        val record = byteArrayOf(0xc0.toByte(), 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 201.toByte()) +
            byteArrayOf(200.toByte()) + ByteArray(200) { 65 }
        return response + (1..recordCount).flatMap { record.toList() }.toByteArray()
    }

    private fun assertDnsAddressAnswer(response: ByteArray, query: ParsedDnsQuery, type: Int) {
        assertTrue("Invalid DNS response for ${query.question.domainName}", DnsMessageValidator.isValidResponse(response, query))
        assertEquals(0, readUnsignedShort(response, 2) and 0x0F)
        assertEquals(1, readUnsignedShort(response, 6))
        val answerOffset = query.questionEndOffset
        assertEquals(type, readUnsignedShort(response, answerOffset + 2))
        val expectedAddress = when (type) {
            1 -> byteArrayOf(203.toByte(), 0, 113, 7)
            28 -> byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte()) + ByteArray(10) + byteArrayOf(0, 7)
            else -> error("Unexpected address query type $type")
        }
        assertEquals(expectedAddress.size, readUnsignedShort(response, answerOffset + 10))
        assertArrayEquals(expectedAddress, response.copyOfRange(answerOffset + 12, answerOffset + 12 + expectedAddress.size))
    }
}
