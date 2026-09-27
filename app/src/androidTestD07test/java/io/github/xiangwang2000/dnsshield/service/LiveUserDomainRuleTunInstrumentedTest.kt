package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.UserDomainRuleEntity
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LiveUserDomainRuleTunInstrumentedTest {
    @Test
    fun liveRuleReloadBlocksAndAllowsThroughTunAndDropsCachedAnswer() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("io.github.xiangwang2000.dnsshield.d07test", context.packageName)
        assertNull(
            "Approve the VPN permission for the .d07test app before running this instrumentation test.",
            VpnService.prepare(context)
        )

        val dao = AppDatabase.getDatabase(context).dnsDao()
        val domain = "d07-live-${System.nanoTime()}.example.com"
        assertNull("Test domain unexpectedly already has a rule", dao.getUserDomainRule(domain, false))

        val upstream = DatagramSocket(null).apply {
            reuseAddress = false
            bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), BuildConfig.DNS_UPSTREAM_PORT))
        }
        val upstreamQueries = AtomicInteger()
        val upstreamFailure = AtomicReference<Throwable?>()
        val upstreamThread = Thread({
            val buffer = ByteArray(4096)
            while (!upstream.isClosed) {
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    upstream.receive(packet)
                    val query = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    if (questionMatchesDomain(query, domain)) upstreamQueries.incrementAndGet()
                    val response = positiveAResponse(query)
                    upstream.send(DatagramPacket(response, response.size, packet.socketAddress))
                } catch (exception: SocketException) {
                    if (!upstream.isClosed) upstreamFailure.set(exception)
                    break
                } catch (exception: Exception) {
                    if (!upstream.isClosed) upstreamFailure.set(exception)
                    break
                }
            }
        }, "d07-test-dns-upstream").apply { isDaemon = true }

        var serviceStarted = false
        var ruleInserted = false
        try {
            dao.replaceUserDomainRule(UserDomainRuleEntity(domain = domain, action = "BLOCK", includeSubdomains = false))
            ruleInserted = true
            upstreamThread.start()

            ContextCompat.startForegroundService(
                context,
                Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
            )
            serviceStarted = true
            awaitState("VPN did not establish a TUN interface") { DnsVpnService.isRunningFlow.value }

            val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            awaitState("Android did not activate the VPN network before DNS queries") {
                val activeNetwork = connectivityManager.activeNetwork
                activeNetwork != null && connectivityManager.getNetworkCapabilities(activeNetwork)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }

            context.startService(
                Intent(context, DnsVpnService::class.java)
                    .setAction(DnsVpnService.ACTION_UPDATE_DNS)
                    .putExtra("primary", "127.0.0.1")
                    .putExtra("dnsName", "D07 fake upstream")
            )
            awaitState("VPN did not apply the fake upstream") {
                DnsVpnService.activeDnsFlow.value == "D07 fake upstream (127.0.0.1)"
            }

            val query = dnsQuery(domain)
            assertEquals(3, awaitRcode(query, 3))

            dao.replaceUserDomainRule(UserDomainRuleEntity(domain = domain, action = "ALLOW", includeSubdomains = false))
            context.startService(reloadIntent(context))
            assertEquals(0, awaitRcode(query, 0))
            assertEquals("Allowed query should reach the local fake upstream once", 1, upstreamQueries.get())
            assertEquals(0, awaitRcode(query, 0))
            assertEquals("Repeated allowed query should use its DNS cache entry", 1, upstreamQueries.get())

            dao.replaceUserDomainRule(UserDomainRuleEntity(domain = domain, action = "BLOCK", includeSubdomains = false))
            context.startService(reloadIntent(context))
            assertEquals("A cached positive answer must not survive the BLOCK rule", 3, awaitRcode(query, 3))
            assertEquals(1, upstreamQueries.get())
            assertNull("Fake upstream failed", upstreamFailure.get())
        } finally {
            try {
                if (serviceStarted) {
                    context.startService(
                        Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)
                    )
                    awaitState("VPN service did not stop after the test", 10_000) {
                        !DnsVpnService.isRunningFlow.value
                    }
                }
            } finally {
                upstream.close()
                try {
                    if (upstreamThread.isAlive) upstreamThread.join(1_000)
                } finally {
                    if (ruleInserted) dao.deleteUserDomainRule(domain, false)
                }
            }
        }
    }

    private fun reloadIntent(context: android.content.Context) =
        Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_RELOAD_DOMAIN_POLICY)

    private fun dnsQuery(domain: String): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { output ->
            output.writeShort(0xD007)
            output.writeShort(0x0100)
            output.writeShort(1)
            output.writeShort(0)
            output.writeShort(0)
            output.writeShort(0)
            domain.split('.').forEach { label ->
                val encoded = label.toByteArray(Charsets.US_ASCII)
                output.writeByte(encoded.size)
                output.write(encoded)
            }
            output.writeByte(0)
            output.writeShort(1)
            output.writeShort(1)
        }
        return bytes.toByteArray()
    }

    private fun questionMatchesDomain(query: ByteArray, domain: String): Boolean {
        val encoded = ByteArrayOutputStream()
        domain.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            encoded.write(bytes.size)
            encoded.write(bytes)
        }
        encoded.write(0)
        val name = encoded.toByteArray()
        return query.size >= 12 + name.size + 4 &&
            name.indices.all { query[12 + it] == name[it] }
    }

    private fun positiveAResponse(query: ByteArray): ByteArray {
        val response = query.copyOf(query.size + 16)
        response[2] = ((query[2].toInt() and 0x01) or 0x80).toByte()
        response[3] = 0x80.toByte()
        response[6] = 0
        response[7] = 1
        var offset = query.size
        response[offset++] = 0xC0.toByte()
        response[offset++] = 0x0C
        response[offset++] = 0
        response[offset++] = 1
        response[offset++] = 0
        response[offset++] = 1
        response[offset++] = 0
        response[offset++] = 0
        response[offset++] = 0
        response[offset++] = 60
        response[offset++] = 0
        response[offset++] = 4
        response[offset++] = 192.toByte()
        response[offset++] = 0
        response[offset++] = 2
        response[offset] = 1
        return response
    }

    private fun awaitRcode(query: ByteArray, expected: Int): Int {
        val deadline = SystemClock.elapsedRealtime() + 15_000
        var lastRcode: Int? = null
        while (SystemClock.elapsedRealtime() < deadline) {
            try {
                val response = queryTun(query)
                lastRcode = response[3].toInt() and 0x0F
                if (lastRcode == expected) return lastRcode
            } catch (_: SocketTimeoutException) {
                // The VPN may still be loading the new policy; retry until the bounded deadline.
            }
            Thread.sleep(50)
        }
        fail("Expected DNS RCODE $expected after live rule reload; last response RCODE was $lastRcode")
        return -1
    }

    private fun queryTun(query: ByteArray): ByteArray = DatagramSocket().use { socket ->
        socket.soTimeout = 700
        socket.send(
            DatagramPacket(
                query,
                query.size,
                InetAddress.getByName(DnsVpnService.DUMMY_DNS_IP),
                53
            )
        )
        val packet = DatagramPacket(ByteArray(4096), 4096)
        socket.receive(packet)
        packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
    }

    private fun awaitState(message: String, timeoutMillis: Long = 15_000, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            if (condition()) return
            Thread.sleep(50)
        }
        fail(message)
    }
}