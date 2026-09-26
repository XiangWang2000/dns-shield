package io.github.xiangwang2000.dnsshield.service

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

class DnsDohHttpClientTest {
    @Test
    fun redirectResponsesNeverSendTheDnsBodyToAnotherEndpoint() {
        // Plain loopback HTTP exercises the real redirect engine without TLS fixtures;
        // production endpoint validation separately requires HTTPS.
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val redirectedRequests = AtomicInteger()
        val query = DnsTestMessages.query()
        val status = AtomicInteger(307)
        server.createContext("/dns-query") { exchange ->
            exchange.use {
                assertContentEquals(query, it.requestBody.readBytes())
                it.responseHeaders.add("Location", "http://127.0.0.1:${server.address.port}/redirected")
                it.sendResponseHeaders(status.get(), -1)
            }
        }
        server.createContext("/redirected") { exchange ->
            exchange.use {
                redirectedRequests.incrementAndGet()
                it.requestBody.readBytes()
                it.sendResponseHeaders(200, -1)
            }
        }
        server.start()
        val client = OkHttpClient.Builder().callTimeout(2, TimeUnit.SECONDS).build()
            .forDohEndpoints(emptyList())
        try {
            for (code in listOf(301, 302, 303, 307, 308)) {
                status.set(code)
                val request = Request.Builder()
                    .url("http://127.0.0.1:${server.address.port}/dns-query")
                    .post(query.toRequestBody())
                    .build()
                client.newCall(request).execute().use { assertEquals(code, it.code) }
                assertEquals(0, redirectedRequests.get())
            }
        } finally {
            server.stop(0)
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdownNow()
        }
    }
}
