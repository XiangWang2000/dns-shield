package io.github.xiangwang2000.dnsshield.service

import android.content.Context
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
import java.io.Closeable
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DohTlsFallbackInstrumentedTest {
    @Test
    fun strictModeReturnsServFailWithoutUdpAfterInvalidTlsCertificate() = runBlocking {
        runTlsFailureScenario(allowPlaintextFallback = false)
    }

    @Test
    fun allowedFallbackUsesUdpAfterTheSameInvalidTlsCertificate() = runBlocking {
        runTlsFailureScenario(allowPlaintextFallback = true)
    }

    private suspend fun runTlsFailureScenario(allowPlaintextFallback: Boolean) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertTrue("This suite must run in the isolated .d08test app", context.packageName.endsWith(".d08test"))
        assertEquals("The D08 test build must route loopback UDP to its unprivileged test port", 15353, BuildConfig.DNS_UDP_PORT)

        val dao = AppDatabase.getDatabase(context).dnsDao()
        val originalServers = dao.getDnsServersList()
        val domain = "d08-${UUID.randomUUID().toString().replace("-", "")}.example.test"
        val tlsServer = RejectingTlsServer(instrumentation.context)
        val udpServer = FakeUdpDnsServer(domain)
        val resolverName = "D08 TLS ${UUID.randomUUID()}"
        var resolverId: Int? = null

        try {
            stopVpnIfRunning(context)
            dao.insertDnsServer(
                DnsServer(
                    name = resolverName,
                    primaryIp = RESOLVER_IP,
                    secondaryIp = null,
                    isCustom = true,
                    isActive = false,
                    allowPlaintextFallback = allowPlaintextFallback,
                    primaryDohUrl = "https://$RESOLVER_IP:${tlsServer.port}/dns-query"
                )
            )
            resolverId = dao.getDnsServersList().first { it.name == resolverName }.id
            assertTrue(dao.setActiveDnsServer(requireNotNull(resolverId)))

            ensureVpnConsent(context)
            startVpn(context)
            awaitActiveVpnNetwork(context)

            val transactionId = System.nanoTime().toInt() and 0xffff
            val response = sendQueryThroughTun(buildDnsQuery(domain, transactionId))

            tlsServer.assertClientRejectedCertificate()
            assertDnsTransaction(response, transactionId)
            assertDnsResponseCode(response, if (allowPlaintextFallback) 0 else 2)
            if (allowPlaintextFallback) {
                assertTrue("TLS failure did not reach UDP/15353 for the test hostname", udpServer.awaitQuery())
                assertEquals("Unexpected target-host UDP query count", 1, udpServer.targetQueryCount.get())
                assertEquals(EXPECTED_ANSWER, response.takeLast(4).map { it.toInt() and 0xff })
            } else {
                assertEquals("Strict TLS mode sent the test hostname over plaintext UDP", 0, udpServer.targetQueryCount.get())
                assertEquals("Strict TLS mode must return an answerless SERVFAIL", 0, dnsAnswerCount(response))
            }
            assertEquals(null, udpServer.failure.get())
        } finally {
            try {
                stopVpnIfRunning(context)
            } finally {
                try {
                    resolverId?.let { dao.deleteDnsServerById(it) }
                    dao.getDnsServersList()
                        .filter { it.name == resolverName }
                        .forEach { dao.deleteDnsServerById(it.id) }
                    originalServers.forEach { dao.insertDnsServer(it) }
                } finally {
                    udpServer.close()
                    tlsServer.close()
                }
            }
        }
    }

    private suspend fun ensureVpnConsent(context: Context) {
        val consentIntent = VpnService.prepare(context) ?: return
        context.startActivity(consentIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        withTimeout(CONSENT_TIMEOUT_MILLIS) {
            while (VpnService.prepare(context) != null) delay(250)
        }
    }

    private suspend fun startVpn(context: Context) {
        ContextCompat.startForegroundService(
            context,
            Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
        )
        withTimeout(SERVICE_TIMEOUT_MILLIS) {
            DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING }
        }
    }

    private suspend fun awaitActiveVpnNetwork(context: Context) {
        val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        withTimeout(SERVICE_TIMEOUT_MILLIS) {
            while (connectivity.activeNetwork?.let(connectivity::getNetworkCapabilities)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != true
            ) {
                delay(100)
            }
        }
    }

    private suspend fun stopVpnIfRunning(context: Context) {
        if (DnsVpnService.lifecycleStateFlow.value == VpnLifecycleState.STOPPED) return
        ContextCompat.startForegroundService(
            context,
            Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)
        )
        withTimeout(SERVICE_TIMEOUT_MILLIS) {
            DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED }
        }
    }

    private fun sendQueryThroughTun(query: ByteArray): ByteArray = DatagramSocket().use { socket ->
        socket.soTimeout = 500
        val request = DatagramPacket(query, query.size,
            InetAddress.getByName(DnsVpnService.DUMMY_DNS_IP), 53)
        val response = DatagramPacket(ByteArray(2048), 2048)
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(QUERY_TIMEOUT_MILLIS.toLong())
        while (true) {
            socket.send(request)
            try { socket.receive(response); break }
            catch (error: java.net.SocketTimeoutException) {
                if (System.nanoTime() >= deadline) throw error
            }
        }
        response.data.copyOf(response.length)
    }

    private fun assertDnsTransaction(response: ByteArray, transactionId: Int) {
        assertTrue("DNS response is too short", response.size >= 12)
        val actualId = ((response[0].toInt() and 0xff) shl 8) or (response[1].toInt() and 0xff)
        assertEquals(transactionId, actualId)
        assertTrue("Packet is not a DNS response", response[2].toInt() and 0x80 != 0)
    }

    private fun assertDnsResponseCode(response: ByteArray, expected: Int) {
        val flags = ((response[2].toInt() and 0xff) shl 8) or (response[3].toInt() and 0xff)
        assertEquals(expected, flags and 0x0f)
    }

    private fun dnsAnswerCount(response: ByteArray): Int =
        ((response[6].toInt() and 0xff) shl 8) or (response[7].toInt() and 0xff)

    private fun buildDnsQuery(domain: String, transactionId: Int): ByteArray {
        val output = ByteArrayOutputStream()
        output.write(transactionId shr 8)
        output.write(transactionId)
        output.write(byteArrayOf(0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
        domain.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            output.write(bytes.size)
            output.write(bytes)
        }
        output.write(0)
        output.write(byteArrayOf(0x00, 0x01, 0x00, 0x01))
        return output.toByteArray()
    }

    private fun buildDnsResponse(query: ByteArray): ByteArray {
        val isAQuery = query.size >= 4 &&
            (query[query.size - 4].toInt() and 0xff) == 0 &&
            (query[query.size - 3].toInt() and 0xff) == 1
        val output = ByteArrayOutputStream()
        output.write(query.copyOfRange(0, 2))
        output.write(byteArrayOf(
            0x81.toByte(), 0x80.toByte(), 0, 1, 0,
            if (isAQuery) 0x01 else 0x00,
            0, 0, 0, 0
        ))
        output.write(query.copyOfRange(12, query.size))
        if (isAQuery) {
            output.write(byteArrayOf(0xc0.toByte(), 0x0c, 0x00, 0x01, 0x00, 0x01))
            output.write(byteArrayOf(0x00, 0x00, 0x00, 0x3c, 0x00, 0x04))
            output.write(byteArrayOf(192.toByte(), 0, 2, 53))
        }
        return output.toByteArray()
    }

    private fun dnsQuestionName(query: ByteArray): String? {
        if (query.size <= 12) return null
        val labels = mutableListOf<String>()
        var offset = 12
        while (offset < query.size) {
            val length = query[offset++].toInt() and 0xff
            if (length == 0) return labels.joinToString(".")
            if (length >= 64 || offset + length > query.size) return null
            labels += String(query, offset, length, Charsets.US_ASCII)
            offset += length
        }
        return null
    }

    private class RejectingTlsServer(testContext: Context) : Closeable {
        private val accepted = CountDownLatch(1)
        private val handshakeFinished = CountDownLatch(1)
        private val handshakeFailure = AtomicReference<Throwable?>()
        private val handshakeSucceeded = AtomicBoolean(false)
        private val serverSocket: SSLServerSocket
        private val worker: Thread
        val port: Int
            get() = serverSocket.localPort

        init {
            val keyStore = KeyStore.getInstance("PKCS12")
            testContext.assets.open(CERT_ASSET).use { keyStore.load(it, CERT_PASSWORD.toCharArray()) }
            val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            keyManagerFactory.init(keyStore, CERT_PASSWORD.toCharArray())
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(keyManagerFactory.keyManagers, null, null)
            serverSocket = sslContext.serverSocketFactory.createServerSocket(
                0,
                1,
                InetAddress.getByName(RESOLVER_IP)
            ) as SSLServerSocket
            worker = Thread {
                var client: SSLSocket? = null
                try {
                    client = serverSocket.accept() as SSLSocket
                    accepted.countDown()
                    client.soTimeout = SERVER_TIMEOUT_MILLIS
                    client.startHandshake()
                    handshakeSucceeded.set(true)
                } catch (exception: SSLException) {
                    handshakeFailure.set(exception)
                } catch (exception: IOException) {
                    if (!serverSocket.isClosed) handshakeFailure.set(exception)
                } finally {
                    try {
                        client?.close()
                    } catch (_: IOException) {
                    }
                    handshakeFinished.countDown()
                }
            }.apply {
                name = "d08-rejecting-tls-server"
                isDaemon = true
                start()
            }
        }

        fun assertClientRejectedCertificate() {
            assertTrue("DoH client never connected to the local TLS endpoint",
                accepted.await(SERVER_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS))
            assertTrue("TLS handshake did not finish after the test certificate was presented",
                handshakeFinished.await(SERVER_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS))
            assertFalse("The client accepted the untrusted test certificate", handshakeSucceeded.get())
            assertNotNull("Expected the client to reject the self-signed test certificate", handshakeFailure.get())
        }

        override fun close() {
            try {
                serverSocket.close()
            } catch (_: IOException) {
            }
            worker.join(1_000)
        }
    }

    private inner class FakeUdpDnsServer(private val expectedDomain: String) : Closeable {
        private val running = AtomicBoolean(true)
        private val requestReceived = CountDownLatch(1)
        private val socket = DatagramSocket(null).apply {
            reuseAddress = true
            bind(InetSocketAddress(InetAddress.getByName(RESOLVER_IP), BuildConfig.DNS_UDP_PORT))
            soTimeout = 200
        }
        val targetQueryCount = AtomicInteger(0)
        val backgroundQueryCount = AtomicInteger(0)
        val failure = AtomicReference<IOException?>()
        private val worker = Thread {
            while (running.get()) {
                val packet = DatagramPacket(ByteArray(2048), 2048)
                try {
                    socket.receive(packet)
                    val query = packet.data.copyOf(packet.length)
                    if (dnsQuestionName(query)?.equals(expectedDomain, ignoreCase = true) == true) {
                        targetQueryCount.incrementAndGet()
                        requestReceived.countDown()
                    } else {
                        backgroundQueryCount.incrementAndGet()
                    }
                    val response = buildDnsResponse(query)
                    socket.send(DatagramPacket(response, response.size, packet.socketAddress))
                } catch (_: SocketTimeoutException) {
                    // Recheck the close flag.
                } catch (exception: IOException) {
                    if (running.get()) failure.set(exception)
                }
            }
        }.apply {
            name = "d08-fake-udp-dns"
            isDaemon = true
            start()
        }

        fun awaitQuery(): Boolean = requestReceived.await(QUERY_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)

        override fun close() {
            running.set(false)
            socket.close()
            worker.join(1_000)
        }
    }

    companion object {
        private const val RESOLVER_IP = "127.0.0.2"
        private const val CERT_ASSET = "d08-test-server.p12"
        private const val CERT_PASSWORD = "d08-test-only-password"
        private const val QUERY_TIMEOUT_MILLIS = 12_000
        private const val SERVER_TIMEOUT_MILLIS = 8_000
        private const val SERVICE_TIMEOUT_MILLIS = 30_000L
        private const val CONSENT_TIMEOUT_MILLIS = 120_000L
        private val EXPECTED_ANSWER = listOf(192, 0, 2, 53)
    }
}
