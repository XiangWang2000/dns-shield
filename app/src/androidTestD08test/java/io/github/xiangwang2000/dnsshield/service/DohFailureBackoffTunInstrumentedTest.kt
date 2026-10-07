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
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Protocol
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DohFailureBackoffTunInstrumentedTest {
    @Test
    fun sameUrlWithDifferentBootstrapKeepsHealthyAlternateDuringBackoff() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Run only in the isolated D08 test package", context.packageName.endsWith(".d08test"))
        assertEquals(15353, BuildConfig.DNS_UPSTREAM_PORT)
        assumeTrue("Approve VPN consent for .d08test before this run", VpnService.prepare(context) == null)

        val dao = AppDatabase.getDatabase(context).dnsDao()
        val originalServers = dao.getDnsServersList()
        val suffix = UUID.randomUUID().toString().replace("-", "").take(8)
        val resolverName = "D08 backoff pair $suffix"
        val domains = (1..4).map { "d08-backoff-$it-$suffix.example.test" }
        val primary = LocalTlsDohServer(PRIMARY_IP, 0, answer = null)
        val secondary = LocalTlsDohServer(
            SECONDARY_IP,
            primary.port,
            answer = ::buildDnsResponse
        )
        val plaintext = PlaintextUdpCounter()
        var resolverId: Int? = null

        try {
            stopVpnIfRunning(context)
            dao.insertDnsServer(
                DnsServer(
                    name = resolverName,
                    primaryIp = PRIMARY_IP,
                    secondaryIp = SECONDARY_IP,
                    isCustom = true,
                    allowPlaintextFallback = false,
                    primaryDohUrl = dohUrl(primary.port),
                    primaryDohBootstrapIps = PRIMARY_IP,
                    secondaryDohUrl = dohUrl(primary.port),
                    secondaryDohBootstrapIps = SECONDARY_IP
                )
            )
            resolverId = dao.getDnsServersList().first { it.name == resolverName }.id
            assertTrue(dao.setActiveDnsServer(requireNotNull(resolverId)))

            ensureVpnConsent(context)
            startVpn(context)
            awaitActiveVpnNetwork(context)
            delay(NETWORK_SETTLE_MILLIS)
            DnsVpnService.setD08TestHttpClient(pinnedD08HttpClient())

            repeat(3) { index ->
                val transactionId = 0x8400 + index
                val response = sendQueryThroughTun(buildDnsQuery(domains[index], transactionId))
                assertDnsResponseCode(response, 0, transactionId)
                assertEquals(1, dnsAnswerCount(response))
            }
            assertEquals("The failing primary should reach the backoff threshold", 3, primary.requestCount.get())
            assertEquals(3, secondary.requestCount.get())

            val recoveredResponse = sendQueryThroughTun(buildDnsQuery(domains[3], 0x8403))
            assertDnsResponseCode(recoveredResponse, 0, 0x8403)
            assertEquals(1, dnsAnswerCount(recoveredResponse))
            assertEquals("A healthy endpoint with a different bootstrap must not clear the primary circuit", 3, primary.requestCount.get())
            assertEquals(4, secondary.requestCount.get())
            assertEquals("Strict DoH mode sent a query over UDP", 0, plaintext.queryCount.get())
            assertNull(primary.failure.get())
            assertNull(secondary.failure.get())
            assertNull(plaintext.failure.get())
        } finally {
            try {
                stopVpnIfRunning(context)
            } finally {
                DnsVpnService.setD08TestHttpClient(null)
                try {
                    resolverId?.let { dao.deleteDnsServerById(it) }
                    dao.getDnsServersList().filter { it.name == resolverName }
                        .forEach { dao.deleteDnsServerById(it.id) }
                    originalServers.forEach { dao.insertDnsServer(it) }
                } finally {
                    plaintext.close()
                    secondary.close()
                    primary.close()
                }
            }
        }
    }

    @Test
    fun lateFailureFromOldResolverGenerationDoesNotTripNewCircuit() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Run only in the isolated D08 test package", context.packageName.endsWith(".d08test"))
        assertEquals(15353, BuildConfig.DNS_UPSTREAM_PORT)
        assumeTrue("Approve VPN consent for .d08test before this run", VpnService.prepare(context) == null)

        val dao = AppDatabase.getDatabase(context).dnsDao()
        val originalServers = dao.getDnsServersList()
        val suffix = UUID.randomUUID().toString().replace("-", "").take(8)
        val initialName = "D08 late DoH $suffix"
        val updatedName = "$initialName updated"
        val oldDomain = "d08-late-old-$suffix.example.test"
        val currentDomains = listOf(
            "d08-late-current-a-$suffix.example.test",
            "d08-late-current-b-$suffix.example.test",
            "d08-late-current-c-$suffix.example.test"
        )
        val primary = LocalTlsDohServer(
            PRIMARY_IP,
            0,
            answer = null,
            holdFirstResponse = true
        )
        val plaintext = PlaintextUdpCounter()
        var resolverId: Int? = null
        var oldQuery: kotlinx.coroutines.Deferred<ByteArray>? = null

        try {
            stopVpnIfRunning(context)
            dao.insertDnsServer(
                DnsServer(
                    name = initialName,
                    primaryIp = PRIMARY_IP,
                    secondaryIp = null,
                    isCustom = true,
                    allowPlaintextFallback = false,
                    primaryDohUrl = dohUrl(primary.port),
                    primaryDohBootstrapIps = PRIMARY_IP
                )
            )
            resolverId = dao.getDnsServersList().first { it.name == initialName }.id
            assertTrue(dao.setActiveDnsServer(requireNotNull(resolverId)))

            ensureVpnConsent(context)
            startVpn(context)
            awaitActiveVpnNetwork(context)
            delay(NETWORK_SETTLE_MILLIS)
            DnsVpnService.setD08TestHttpClient(pinnedD08HttpClient())

            oldQuery = async(Dispatchers.IO) {
                sendQueryThroughTunOnce(buildDnsQuery(oldDomain, 0x8500))
            }
            assertTrue(
                "The old generation did not reach the local DoH server",
                primary.firstRequest.await(SERVER_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)
            )
            assertTrue(
                "The old HTTP response was not held at the test barrier",
                primary.firstResponseHeld.await(SERVER_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)
            )
            assertFalse("The old request completed before the resolver fence", requireNotNull(oldQuery).isCompleted)

            val updated = requireNotNull(dao.getDnsServerById(requireNotNull(resolverId))).copy(name = updatedName)
            dao.insertDnsServer(updated)
            val updateIntent = Intent(context, DnsVpnService::class.java).apply {
                action = DnsVpnService.ACTION_UPDATE_DNS
                putExtra("resolverId", requireNotNull(resolverId))
                putExtra(
                    DnsVpnService.EXTRA_RESOLVER_COMMAND_REVISION,
                    ResolverCommandRuntime.revisions.next()
                )
            }
            context.startService(updateIntent)
            withTimeout(SERVICE_TIMEOUT_MILLIS) {
                DnsVpnService.activeDnsFlow.first { it == "$updatedName ($PRIMARY_IP)" }
            }

            currentDomains.take(2).forEachIndexed { index, domain ->
                val transactionId = 0x8501 + index
                val response = sendQueryThroughTun(buildDnsQuery(domain, transactionId))
                assertDnsResponseCode(response, 2, transactionId)
                assertEquals(0, dnsAnswerCount(response))
            }
            assertEquals("Expected two new-generation failures before releasing the old response", 3, primary.requestCount.get())
            assertFalse("The old request timed out before its late failure could be observed", requireNotNull(oldQuery).isCompleted)

            primary.releaseFirstResponse()
            val oldResponse = withTimeout(QUERY_TIMEOUT_MILLIS.toLong()) { requireNotNull(oldQuery).await() }
            assertDnsResponseCode(oldResponse, 2, 0x8500)
            assertEquals("The released old-generation failure was not processed", 3, primary.requestCount.get())

            val thirdResponse = sendQueryThroughTun(buildDnsQuery(currentDomains[2], 0x8503))
            assertDnsResponseCode(thirdResponse, 2, 0x8503)
            assertEquals(
                "An old-generation completion polluted the new resolver backoff state",
                4,
                primary.requestCount.get()
            )
            assertEquals("Strict DoH mode sent a query over UDP", 0, plaintext.queryCount.get())
            assertNull(primary.failure.get())
            assertNull(plaintext.failure.get())
        } finally {
            primary.releaseFirstResponse()
            try {
                stopVpnIfRunning(context)
            } finally {
                DnsVpnService.setD08TestHttpClient(null)
                try {
                    resolverId?.let { dao.deleteDnsServerById(it) }
                    dao.getDnsServersList().filter { it.name == initialName || it.name == updatedName }
                        .forEach { dao.deleteDnsServerById(it.id) }
                    originalServers.forEach { dao.insertDnsServer(it) }
                } finally {
                    plaintext.close()
                    primary.close()
                }
            }
        }
    }

    private fun pinnedD08HttpClient(): OkHttpClient {
        val fixtureStore = KeyStore.getInstance("PKCS12")
        InstrumentationRegistry.getInstrumentation().context.assets.open(CERT_ASSET).use {
            fixtureStore.load(it, CERT_PASSWORD.toCharArray())
        }
        val fixtureAlias = fixtureStore.aliases().nextElement()
        val fixtureCertificate = fixtureStore.getCertificate(fixtureAlias) as X509Certificate
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("d08-local-doh-fixture", fixtureCertificate)
        }
        val trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(trustStore)
        }
        val trustManager = trustFactory.trustManagers.filterIsInstance<X509TrustManager>().single()
        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustManager), null)
        }
        return DnsVpnService.getOkHttpClient().newBuilder()
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .hostnameVerifier { hostname, session ->
                hostname == TEST_HOSTNAME &&
                    session.peerCertificates.firstOrNull()?.encoded?.contentEquals(fixtureCertificate.encoded) == true
            }
            .protocols(listOf(Protocol.HTTP_1_1))
            .build()
    }

    private fun dohUrl(port: Int): String = "https://$TEST_HOSTNAME:$port/dns-query"

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

    private fun sendQueryThroughTun(query: ByteArray): ByteArray = DatagramSocket().use { socket ->
        socket.soTimeout = QUERY_RETRY_MILLIS
        val request = DatagramPacket(query, query.size, InetAddress.getByName(DnsVpnService.DUMMY_DNS_IP), 53)
        val response = DatagramPacket(ByteArray(2048), 2048)
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(QUERY_TIMEOUT_MILLIS.toLong())
        while (System.nanoTime() < deadline) {
            socket.send(request)
            try {
                socket.receive(response)
                return@use response.data.copyOf(response.length)
            } catch (_: SocketTimeoutException) {
                // Retransmit while waiting for the VPN service's single bounded upstream attempt.
            }
        }
        throw AssertionError("Timed out waiting for a DNS response through the VPN TUN")
    }

    private fun sendQueryThroughTunOnce(query: ByteArray): ByteArray = DatagramSocket().use { socket ->
        socket.soTimeout = QUERY_TIMEOUT_MILLIS
        val request = DatagramPacket(query, query.size, InetAddress.getByName(DnsVpnService.DUMMY_DNS_IP), 53)
        socket.send(request)
        val response = DatagramPacket(ByteArray(2048), 2048)
        socket.receive(response)
        response.data.copyOf(response.length)
    }

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
        val output = ByteArrayOutputStream()
        output.write(query.copyOfRange(0, 2))
        output.write(byteArrayOf(0x81.toByte(), 0x80.toByte(), 0, 1, 0, 1, 0, 0, 0, 0))
        output.write(query.copyOfRange(12, query.size))
        output.write(byteArrayOf(0xc0.toByte(), 0x0c, 0, 1, 0, 1))
        output.write(byteArrayOf(0, 0, 0, 60, 0, 4, 192.toByte(), 0, 2, 53))
        return output.toByteArray()
    }

    private fun assertDnsResponseCode(response: ByteArray, expected: Int, transactionId: Int) {
        assertTrue("DNS response is too short", response.size >= 12)
        val actualId = ((response[0].toInt() and 0xff) shl 8) or (response[1].toInt() and 0xff)
        assertEquals("DNS transaction ID changed", transactionId, actualId)
        val flags = ((response[2].toInt() and 0xff) shl 8) or (response[3].toInt() and 0xff)
        assertTrue("Packet is not a DNS response", flags and 0x8000 != 0)
        assertEquals(expected, flags and 0x000f)
    }

    private fun dnsAnswerCount(response: ByteArray): Int =
        ((response[6].toInt() and 0xff) shl 8) or (response[7].toInt() and 0xff)

    private class LocalTlsDohServer(
        bindAddress: String,
        requestedPort: Int,
        private val answer: ((ByteArray) -> ByteArray)?,
        private val holdFirstResponse: Boolean = false
    ) : Closeable {
        val requestCount = AtomicInteger()
        val firstRequest = CountDownLatch(1)
        val firstResponseHeld = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        private val releaseFirst = CountDownLatch(if (holdFirstResponse) 1 else 0)
        private val running = AtomicBoolean(true)
        private val handlers = Executors.newCachedThreadPool()
        private val serverSocket: SSLServerSocket
        private val acceptor: Thread

        val port: Int
            get() = serverSocket.localPort

        init {
            val keyStore = KeyStore.getInstance("PKCS12")
            InstrumentationRegistry.getInstrumentation().context.assets.open(CERT_ASSET).use {
                keyStore.load(it, CERT_PASSWORD.toCharArray())
            }
            val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            keyManagerFactory.init(keyStore, CERT_PASSWORD.toCharArray())
            val serverContext = SSLContext.getInstance("TLS").apply {
                init(keyManagerFactory.keyManagers, null, null)
            }
            serverSocket = serverContext.serverSocketFactory.createServerSocket(
                requestedPort,
                SERVER_BACKLOG,
                InetAddress.getByName(bindAddress)
            ) as SSLServerSocket
            acceptor = Thread {
                while (running.get()) {
                    try {
                        val connection = serverSocket.accept() as SSLSocket
                        handlers.execute { handle(connection) }
                    } catch (_: SocketTimeoutException) {
                        // Check the close flag again.
                    } catch (exception: IOException) {
                        if (running.get()) failure.set(exception)
                    }
                }
            }.apply {
                name = "d08-local-doh-accept"
                isDaemon = true
                start()
            }
        }

        private fun readHttpRequestBody(input: InputStream): ByteArray {
            val headerBytes = ByteArrayOutputStream()
            val delimiter = byteArrayOf(13, 10, 13, 10)
            var matched = 0
            while (matched < delimiter.size) {
                val value = input.read()
                if (value < 0) throw IOException("EOF before the HTTP request headers ended")
                headerBytes.write(value)
                matched = when {
                    value == delimiter[matched].toInt() -> matched + 1
                    value == delimiter[0].toInt() -> 1
                    else -> 0
                }
                if (headerBytes.size() > MAX_HTTP_HEADER_BYTES) {
                    throw IOException("HTTP request headers exceeded the test limit")
                }
            }
            val headers = String(headerBytes.toByteArray(), Charsets.ISO_8859_1)
            val contentLength = headers.lineSequence()
                .firstOrNull { it.startsWith("Content-Length:", ignoreCase = true) }
                ?.substringAfter(":")
                ?.trim()
                ?.toIntOrNull()
                ?: throw IOException("The DoH request did not include Content-Length")
            val body = ByteArray(contentLength)
            var offset = 0
            while (offset < body.size) {
                val count = input.read(body, offset, body.size - offset)
                if (count < 0) throw IOException("EOF before the DoH request body ended")
                offset += count
            }
            return body
        }

        private fun handle(connection: SSLSocket) {
            try {
                connection.use {
                    it.soTimeout = SERVER_TIMEOUT_MILLIS
                    it.startHandshake()
                    val query = readHttpRequestBody(it.inputStream)
                    val requestNumber = requestCount.incrementAndGet()
                    firstRequest.countDown()
                    if (holdFirstResponse && requestNumber == 1) {
                        firstResponseHeld.countDown()
                        if (!releaseFirst.await(SERVER_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)) {
                            throw SocketTimeoutException("Test did not release the held DoH response")
                        }
                    }
                    val responseBody = answer?.invoke(query)
                    val status = if (responseBody == null) 503 else 200
                    val statusText = if (status == 200) "OK" else "Service Unavailable"
                    val header = "HTTP/1.1 $status $statusText\r\n" +
                        "Content-Length: ${responseBody?.size ?: 0}\r\n" +
                        "Content-Type: application/dns-message\r\n" +
                        "Connection: close\r\n\r\n"
                    it.outputStream.write(header.toByteArray(Charsets.US_ASCII))
                    if (responseBody != null) it.outputStream.write(responseBody)
                    it.outputStream.flush()
                }
            } catch (exception: Exception) {
                if (running.get()) failure.compareAndSet(null, exception)
            }
        }

        fun releaseFirstResponse() {
            releaseFirst.countDown()
        }

        override fun close() {
            running.set(false)
            releaseFirst.countDown()
            try {
                serverSocket.close()
            } catch (_: IOException) {
            }
            handlers.shutdownNow()
            acceptor.interrupt()
            acceptor.join(1_000)
        }
    }

    private class PlaintextUdpCounter : Closeable {
        val queryCount = AtomicInteger()
        val failure = AtomicReference<Throwable?>()
        private val running = AtomicBoolean(true)
        private val socket = DatagramSocket(null).apply {
            reuseAddress = true
            bind(InetSocketAddress(InetAddress.getByName(PRIMARY_IP), BuildConfig.DNS_UPSTREAM_PORT))
            soTimeout = 200
        }
        private val worker = Thread {
            while (running.get()) {
                val packet = DatagramPacket(ByteArray(2048), 2048)
                try {
                    socket.receive(packet)
                    queryCount.incrementAndGet()
                } catch (_: SocketTimeoutException) {
                    // Check the close flag again.
                } catch (exception: IOException) {
                    if (running.get()) failure.set(exception)
                }
            }
        }.apply {
            name = "d08-strict-plaintext-counter"
            isDaemon = true
            start()
        }

        override fun close() {
            running.set(false)
            socket.close()
            worker.join(1_000)
        }
    }

    companion object {
        private const val PRIMARY_IP = "127.0.0.2"
        private const val SECONDARY_IP = "127.0.0.1"
        private const val TEST_HOSTNAME = "doh.example.test"
        private const val CERT_ASSET = "d08-test-server.p12"
        private const val CERT_PASSWORD = "d08-test-only-password"
        private const val QUERY_TIMEOUT_MILLIS = 12_000
        private const val QUERY_RETRY_MILLIS = 500
        private const val SERVER_TIMEOUT_MILLIS = 10_000
        private const val SERVER_BACKLOG = 16
        private const val MAX_HTTP_HEADER_BYTES = 16 * 1024
        private const val SERVICE_TIMEOUT_MILLIS = 30_000L
        private const val NETWORK_SETTLE_MILLIS = 1_000L
        private const val CONSENT_TIMEOUT_MILLIS = 120_000L
    }
}
