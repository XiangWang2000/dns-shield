package io.github.xiangwang2000.dnsshield.service

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody.Companion.toResponseBody

class DnsDohHttpClientTest {
    @Test
    fun rejectsHttpErrorAndWrongDnsBodyBeforeAcceptingValidReply() = runBlocking {
        // The interceptor returns an HTTPS response without contacting a live server.
        // Endpoint parsing and Android certificate trust are covered separately.
        val queryBytes = DnsTestMessages.query()
        val query = (DnsMessageValidator.parseQuery(queryBytes) as DnsQueryParseResult.Valid).query
        val valid = DnsTestMessages.response(queryBytes)
        val status = AtomicInteger(503)
        val body = AtomicReference(valid)
        val requests = AtomicInteger()
        val logged = mutableListOf<String>()
        val client = OkHttpClient.Builder().addInterceptor { chain ->
            requests.incrementAndGet()
            Response.Builder()
                .request(chain.request())
                .protocol(Protocol.HTTP_1_1)
                .code(status.get())
                .message("fake DoH")
                .header("Content-Type", "application/dns-message")
                .body(body.get().toResponseBody("application/dns-message".toMediaType()))
                .build()
        }.build().forDohEndpoint(DnsDohEndpoint("https://dns.example.test/dns-query", "dns.example.test", emptyList(), true))
        val url = "https://dns.example.test/dns-query"
        suspend fun lookup() = client.lookupDoh(
            url,
            query,
            DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 1_000)
        ) { message, _ -> synchronized(logged) { logged += message } }
        try {
            assertNull(lookup())
            assertEquals(true, synchronized(logged) { logged.any { "HTTP 503" in it } })

            status.set(200)
            body.set(DnsTestMessages.response(queryBytes, name = "wrong.example"))
            assertNull(lookup())

            body.set(valid)
            assertContentEquals(valid, lookup())
            assertEquals(3, requests.get())
        } finally {
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdownNow()
        }
    }

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
            .forDohEndpoint(DnsDohEndpoint("https://dns.example.test/dns-query", "dns.example.test", emptyList(), true))
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
