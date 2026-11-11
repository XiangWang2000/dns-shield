package io.github.xiangwang2000.dnsshield.service

import android.content.Intent
import android.net.VpnService
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.DnsServer
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.util.Locale
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class UdpPrimaryFailoverInstrumentedTest {
    @Test
    fun silentPrimaryAndResponsiveBackup() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".d08test"))
        assertNull("Approve the isolated VPN before execution", VpnService.prepare(context))
        val arguments = InstrumentationRegistry.getArguments()
        val expectAdaptive = arguments.getString("expect_adaptive") != "false"
        val runLabel = arguments.getString("run_label") ?: "manual"
        val dao = AppDatabase.getDatabase(context).dnsDao()
        val previous = dao.getActiveDnsServer()
        val suffix = "udp-${SystemClock.elapsedRealtimeNanos().toString(36)}.example.test"
        val resolverName = "D08 UDP A/B $suffix"
        val resolver = DnsServer(
            name = resolverName,
            primaryIp = "127.0.0.2",
            secondaryIp = "127.0.0.1",
            isCustom = true,
            allowPlaintextFallback = true
        )

        var resolverId: Int? = null
        LoopbackResolver(resolver.primaryIp, suffix, 20, responds = false).use { primary ->
            LoopbackResolver(requireNotNull(resolver.secondaryIp), suffix, 10, responds = true).use { secondary ->
                try {
                    dao.insertDnsServer(resolver)
                    val id = dao.getDnsServersList().single { it.name == resolverName }.id
                    resolverId = id
                    assertTrue(dao.setActiveDnsServer(id))
                    ContextCompat.startForegroundService(
                        context,
                        Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
                    )
                    withTimeout(25_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING } }
                    withTimeout(15_000) {
                        DnsVpnService.underlyingNetworkConnectivityFlow.first { it == UnderlyingNetworkConnectivity.ONLINE }
                    }

                    val elapsed = (1..6).map { index -> query("sample-$index.$suffix", index, expectedAnswer = 10) }
                    val expectedPrimaryRequests = if (expectAdaptive) 2 else elapsed.size
                    assertEquals(expectedPrimaryRequests, primary.requests.get())
                    assertEquals(elapsed.size, secondary.requests.get())
                    // A healthy primary can still answer if the preferred backup stops responding.
                    primary.responds = true
                    secondary.responds = false
                    val recovery = query("backup-down.$suffix", 7, expectedAnswer = 20)
                    val nextPrimary = query("primary-recovered.$suffix", 8, expectedAnswer = 20)
                    assertEquals(expectedPrimaryRequests + 2, primary.requests.get())
                    assertEquals(elapsed.size + if (expectAdaptive) 1 else 0, secondary.requests.get())
                    println(
                        "UDP_FAILOVER_AB run=$runLabel expect_adaptive=$expectAdaptive successful=${elapsed.size} " +
                            "primary_requests=$expectedPrimaryRequests secondary_requests=${elapsed.size} " +
                            "elapsed_ms=${elapsed.joinToString(",") { formatMillis(it) }} " +
                            "recovery_ms=${formatMillis(recovery)} next_primary_ms=${formatMillis(nextPrimary)}"
                    )
                } finally {
                    try {
                        context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
                        withTimeout(15_000) { DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED } }
                    } finally {
                        previous?.let { dao.setActiveDnsServer(it.id) }
                        resolverId?.let { dao.deleteDnsServerById(it) }
                    }
                }
            }
        }
    }

    private fun formatMillis(value: Double) = "%.3f".format(Locale.ROOT, value)

    private fun query(domain: String, id: Int, expectedAnswer: Int): Double {
        val wire = (listOf<Byte>(0, id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            domain.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray(Charsets.US_ASCII).toList() } +
            listOf<Byte>(0, 0, 1, 0, 1)).toByteArray()
        val started = SystemClock.elapsedRealtimeNanos()
        DatagramSocket().use { client ->
            client.soTimeout = 8_000
            client.connect(InetSocketAddress(InetAddress.getByName("10.0.0.1"), 53))
            client.send(DatagramPacket(wire, wire.size))
            val packet = DatagramPacket(ByteArray(512), 512)
            client.receive(packet)
            val response = packet.data.copyOf(packet.length)
            val parsed = (DnsMessageValidator.parseQuery(wire) as DnsQueryParseResult.Valid).query
            assertTrue(DnsMessageValidator.isValidResponse(response, parsed))
            assertEquals(0, response[3].toInt() and 0x0f)
            assertEquals(expectedAnswer, response.last().toInt() and 0xff)
        }
        return (SystemClock.elapsedRealtimeNanos() - started) / 1_000_000.0
    }

    private class LoopbackResolver(
        host: String,
        private val suffix: String,
        private val answer: Int,
        @Volatile var responds: Boolean
    ) : AutoCloseable {
        val requests = AtomicInteger()
        private val socket = DatagramSocket(InetSocketAddress(InetAddress.getByName(host), BuildConfig.DNS_UPSTREAM_PORT))
        private val worker = thread(isDaemon = true, name = "udp-failover-fixture-$host") {
            val packet = DatagramPacket(ByteArray(512), 512)
            while (!socket.isClosed) {
                try {
                    packet.length = packet.data.size
                    socket.receive(packet)
                    val wire = packet.data.copyOf(packet.length)
                    val query = (DnsMessageValidator.parseQuery(wire) as? DnsQueryParseResult.Valid)?.query ?: continue
                    if (query.question.domainName?.endsWith(".$suffix") != true) continue
                    requests.incrementAndGet()
                    if (!responds) continue
                    val response = wire + byteArrayOf(
                        0xc0.toByte(), 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4,
                        192.toByte(), 0, 2, answer.toByte()
                    )
                    response[2] = 0x81.toByte()
                    response[3] = 0x80.toByte()
                    response[7] = 1
                    socket.send(DatagramPacket(response, response.size, packet.socketAddress))
                } catch (failure: SocketException) {
                    if (!socket.isClosed) throw failure
                }
            }
        }

        override fun close() {
            socket.close()
            worker.join(1_000)
        }
    }
}
