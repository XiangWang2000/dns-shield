package io.github.xiangwang2000.dnsshield.service

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import java.net.InetSocketAddress
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.async
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import okhttp3.EventListener
import okhttp3.Call
import okhttp3.Connection
import okhttp3.Handshake
import okhttp3.OkHttpClient

class DohEndpointHttpsTest {
    @Test
    fun acceptsMaximumLengthDnsResponseOverLocalHttps() = runBlocking {
        val queryBytes = DnsTestMessages.query(type = 16)
        val expected = DnsTestMessages.responseWithLargeTextAnswer(queryBytes)
        LocalHttpsDns("127.0.0.1", responseFor = { request ->
            assertContentEquals(queryBytes, request)
            expected
        }).use { server ->
            val ep = endpoint("dns.example.test", server.port, "large-response", "127.0.0.1")
            val base = trustedClient()
            try {
                val query = (DnsMessageValidator.parseQuery(queryBytes) as DnsQueryParseResult.Valid).query
                val response = base.forDohEndpoint(ep).lookupDoh(
                    ep.url, query,
                    DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 3_000)
                ) { _, _ -> }
                assertContentEquals(expected, response)
                assertEquals(DnsMessageValidator.MAX_DNS_RESPONSE_BYTES, response?.size)
            } finally { closeClient(base) }
        }
    }

    @Test
    fun sameHostnameEndpointsUseTheirOwnBootstrapAddress() = runBlocking {
        LocalHttpsDns("127.0.0.1").use { primary ->
            LocalHttpsDns("127.0.0.2", primary.port).use { secondary ->
                val a = endpoint("dns.example.test", primary.port, "primary", "127.0.0.1")
                val b = endpoint("dns.example.test", secondary.port, "secondary", "127.0.0.2")
                val base = trustedClient()
                try {
                    lookup(base.forDohEndpoint(a), a, "primary.example")
                    assertEquals(listOf("/primary"), primary.paths.toList())
                    assertEquals(emptyList(), secondary.paths.toList())
                    lookup(base.forDohEndpoint(b), b, "secondary.example")
                    assertEquals(listOf("/secondary"), secondary.paths.toList())
                } finally { closeClient(base) }
            }
        }
    }

    @Test
    fun repeatedUniqueQueriesMeasureConnectionAndTlsCounts() = runBlocking {
        LocalHttpsDns("127.0.0.1").use { server ->
            val connects = AtomicInteger()
            val handshakes = AtomicInteger()
            val base = trustedClient().newBuilder().eventListener(object : EventListener() {
                override fun connectionAcquired(call: Call, connection: Connection) { connects.incrementAndGet() }
                override fun secureConnectEnd(call: Call, handshake: Handshake?) { handshakes.incrementAndGet() }
            }).build()
            val ep = endpoint("dns.example.test", server.port, "dns-query", "127.0.0.1")
            try {
                repeat(5) { lookup(base.forDohEndpoint(ep), ep, "unique-$it.example") }
                assertEquals(5, server.paths.size)
                assertEquals(5, connects.get())
                println("DOH_POOL_BASELINE unique_queries=5 acquired=${connects.get()} tls=${handshakes.get()}")
                assertEquals(5, handshakes.get(), "Baseline must reproduce per-query TLS before caching clients")
            } finally { closeClient(base) }
        }
    }

    @Test
    fun emptySecondaryCannotOverridePrimaryAndOtherHostsAndPortsRemainBound() = runBlocking {
        LocalHttpsDns("127.0.0.1").use { first ->
            LocalHttpsDns("127.0.0.2").use { second ->
                val primary = endpoint("dns.example.test", first.port, "primary", "127.0.0.1")
                val empty = primary.copy(url = "https://dns.example.test:${second.port}/empty", bootstrapAddresses = emptyList())
                val other = endpoint("other.example.test", second.port, "other", "127.0.0.2")
                val sameHostOtherPort = endpoint("dns.example.test", second.port, "other-port", "127.0.0.2")
                val builtIn = endpoint("dns.google", first.port, "built-in", "127.0.0.1").copy(isCustom = false)
                val base = trustedClient()
                try {
                    kotlin.test.assertFailsWith<java.net.UnknownHostException> {
                        DohBootstrapDns.forEndpoint(empty).lookup(empty.hostname)
                    }
                    lookup(base.forDohEndpoint(primary), primary, "primary-with-empty-secondary.example")
                    lookup(base.forDohEndpoint(other), other, "other.example")
                    lookup(base.forDohEndpoint(sameHostOtherPort), sameHostOtherPort, "other-port.example")
                    lookup(base.forDohEndpoint(builtIn), builtIn, "built-in.example")
                    assertEquals(listOf("/primary", "/built-in"), first.paths.toList())
                    assertEquals(listOf("/other", "/other-port"), second.paths.toList())
                } finally { closeClient(base) }
            }
        }
    }

    @Test
    fun hostnameVerificationRejectsCertificateForAnotherHost() = runBlocking {
        LocalHttpsDns("127.0.0.1").use { server ->
            val endpoint = endpoint("wrong.example.test", server.port, "dns-query", "127.0.0.1")
            val base = trustedClient()
            try {
                val bytes = DnsTestMessages.query()
                val query = (DnsMessageValidator.parseQuery(bytes) as DnsQueryParseResult.Valid).query
                kotlin.test.assertNull(base.forDohEndpoint(endpoint).lookupDoh(endpoint.url, query,
                    DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 3000)) { _, _ -> })
                assertEquals(emptyList(), server.paths.toList())
            } finally { closeClient(base) }
        }
    }

    @Test
    fun cachedEndpointClientReusesConnectionAcrossUniqueQueriesAndRetiresOnChange() = runBlocking {
        LocalHttpsDns("127.0.0.1").use { first ->
            LocalHttpsDns("127.0.0.2", first.port).use { second ->
                val handshakes = AtomicInteger()
                val base = trustedClient().newBuilder().eventListener(object : EventListener() {
                    override fun secureConnectEnd(call: Call, handshake: Handshake?) { handshakes.incrementAndGet() }
                }).build()
                val primary = endpoint("dns.example.test", first.port, "primary", "127.0.0.1")
                val backup = endpoint("dns.example.test", second.port, "backup", "127.0.0.2")
                val configuration = listOf(primary, backup)
                val cache = DohEndpointClientCache()
                try {
                    repeat(5) { lookup(cache.clientFor(base, configuration, primary), primary, "cached-$it.example") }
                    assertEquals(5, first.paths.size)
                    assertEquals(1, handshakes.get(), "Unique DNS queries should reuse one HTTPS connection")
                    println("DOH_POOL_CANDIDATE unique_queries=5 tls=${handshakes.get()}")
                    lookup(cache.clientFor(base, configuration, backup), backup, "backup.example")
                    assertEquals(listOf("/backup"), second.paths.toList())
                    assertEquals(2, handshakes.get())
                    val edited = primary.copy(bootstrapAddresses = listOf("127.0.0.2"))
                    lookup(cache.clientFor(base, listOf(edited, backup), edited), edited, "edited-bootstrap.example")
                    assertEquals(listOf("/backup", "/primary"), second.paths.toList())
                    assertEquals(3, handshakes.get(), "Bootstrap edits must retire DNS identity")
                    val nextNetworkBase = base.newBuilder().build()
                    lookup(cache.clientFor(nextNetworkBase, listOf(edited, backup), edited), edited, "new-network.example")
                    assertEquals(4, handshakes.get(), "New network/TLS base must retire endpoint clients")
                } finally { closeClient(base) }
            }
        }
    }

    @Test
    fun cancellationEndsOnlyTheCallAndCachedClientCanServeNextQuery() = runBlocking {
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val calls = AtomicInteger()
        LocalHttpsDns("127.0.0.1", beforeReply = {
            if (calls.incrementAndGet() == 1) {
                entered.countDown()
                check(release.await(3, java.util.concurrent.TimeUnit.SECONDS))
            }
        }).use { server ->
            val ep = endpoint("dns.example.test", server.port, "dns-query", "127.0.0.1")
            val base = trustedClient()
            val cache = DohEndpointClientCache()
            try {
                val job = async {
                    lookup(cache.clientFor(base, listOf(ep), ep), ep, "cancelled.example")
                }
                kotlin.test.assertTrue(kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                    entered.await(3, java.util.concurrent.TimeUnit.SECONDS)
                })
                job.cancel()
                job.join()
                kotlin.test.assertTrue(job.isCancelled)
                release.countDown()
                lookup(cache.clientFor(base, listOf(ep), ep), ep, "after-cancel.example")
                assertEquals(2, calls.get())
            } finally {
                release.countDown()
                closeClient(base)
            }
        }
    }

    private fun endpoint(host: String, port: Int, path: String, ip: String) =
        DnsDohEndpoint("https://$host:$port/$path", host, listOf(ip), true)

    private suspend fun lookup(client: OkHttpClient, endpoint: DnsDohEndpoint, domain: String) {
        val bytes = DnsTestMessages.query(name = domain)
        val query = (DnsMessageValidator.parseQuery(bytes) as DnsQueryParseResult.Valid).query
        val response = client.lookupDoh(endpoint.url, query,
            DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 3000)) { _, _ -> }
        assertContentEquals(DnsTestMessages.response(bytes), response)
    }

    private class LocalHttpsDns(
        ip: String,
        requestedPort: Int = 0,
        private val beforeReply: () -> Unit = {},
        private val responseFor: (ByteArray) -> ByteArray = { DnsTestMessages.response(it) }
    ) : AutoCloseable {
        val paths = java.util.concurrent.CopyOnWriteArrayList<String>()
        private val server = HttpsServer.create(InetSocketAddress(ip, requestedPort), 0).apply {
            httpsConfigurator = HttpsConfigurator(sslContext())
            createContext("/") { exchange ->
                exchange.use {
                    paths += it.requestURI.path
                    val request = it.requestBody.readBytes()
                    beforeReply()
                    val response = responseFor(request)
                    it.responseHeaders.set("Content-Type", "application/dns-message")
                    it.sendResponseHeaders(200, response.size.toLong())
                    it.responseBody.write(response)
                }
            }
            start()
        }
        val port get() = server.address.port
        override fun close() = server.stop(0)
    }

    companion object {
        private fun keyStore(): KeyStore = KeyStore.getInstance("PKCS12").apply {
            DohEndpointHttpsTest::class.java.getResourceAsStream("/doh-local-test.p12").use {
                load(requireNotNull(it), "test-only-password".toCharArray())
            }
        }
        private fun sslContext(): SSLContext {
            val km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
                init(keyStore(), "test-only-password".toCharArray())
            }
            return SSLContext.getInstance("TLS").apply { init(km.keyManagers, null, null) }
        }
        private fun trustedClient(): OkHttpClient {
            val tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(keyStore()) }
            val trust = tm.trustManagers.single() as X509TrustManager
            val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
            return OkHttpClient.Builder().sslSocketFactory(context.socketFactory, trust).build()
        }
        private fun closeClient(client: OkHttpClient) {
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdownNow()
        }
    }
}