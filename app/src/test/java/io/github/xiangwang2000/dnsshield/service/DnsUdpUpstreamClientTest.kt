package io.github.xiangwang2000.dnsshield.service

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsUdpUpstreamClientTest {
    private class QueuedDispatcher : CoroutineDispatcher() {
        private var pending: Runnable? = null

        override fun dispatch(context: CoroutineContext, block: Runnable) {
            pending = block
        }

        fun runPending() {
            checkNotNull(pending).run()
        }
    }

    @Test
    fun ignoresWrongSourceIdAndQuestionUntilAValidResponseArrives() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val wrongSource = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val serverFailure = AtomicReference<Throwable?>()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val expectedResponse = DnsTestMessages.response(queryBytes)

        val fakeUpstream = thread(name = "fake-dns-upstream") {
            try {
                val request = DatagramPacket(ByteArray(4096), 4096)
                server.receive(request)
                wrongSource.send(DatagramPacket(expectedResponse, expectedResponse.size, request.address, request.port))

                val wrongId = expectedResponse.copyOf().also { it[1] = (it[1].toInt() xor 1).toByte() }
                server.send(DatagramPacket(wrongId, wrongId.size, request.address, request.port))

                val wrongQuestion = DnsTestMessages.response(queryBytes, name = "other.example")
                server.send(DatagramPacket(wrongQuestion, wrongQuestion.size, request.address, request.port))
                server.send(DatagramPacket(expectedResponse, expectedResponse.size, request.address, request.port))
            } catch (failure: Throwable) {
                serverFailure.set(failure)
            }
        }

        try {
            val response = DnsUdpUpstreamClient.queryBlocking(client, query, loopback, server.localPort, 2000)
            assertContentEquals(expectedResponse, response)
            fakeUpstream.join(2000)
            assertTrue(!fakeUpstream.isAlive)
            assertNull(serverFailure.get())
        } finally {
            client.close()
            wrongSource.close()
            server.close()
            fakeUpstream.join(2000)
        }
    }

    @Test
    fun returnsNullWhenOnlyMalformedResponsesArrive() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query

        val fakeUpstream = thread {
            val request = DatagramPacket(ByteArray(4096), 4096)
            server.receive(request)
            val malformed = byteArrayOf(0x12, 0x34)
            server.send(DatagramPacket(malformed, malformed.size, request.address, request.port))
        }

        try {
            assertNull(DnsUdpUpstreamClient.queryBlocking(client, query, loopback, server.localPort, 150))
            fakeUpstream.join(1000)
            assertTrue(!fakeUpstream.isAlive)
        } finally {
            client.close()
            server.close()
            fakeUpstream.join(1000)
        }
    }

    @Test
    fun rejectsDatagramsLargerThanTheDnsMessageLimit() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query(edns = true, udpPayloadSize = DnsMessageValidator.MAX_DNS_MESSAGE_BYTES)
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val fullLengthResponse = DnsTestMessages.responseWithOptPadding(
            queryBytes,
            targetSize = DnsMessageValidator.MAX_DNS_MESSAGE_BYTES,
            udpPayloadSize = DnsMessageValidator.MAX_DNS_MESSAGE_BYTES
        )
        kotlin.test.assertTrue(DnsMessageValidator.isValidResponse(fullLengthResponse, query))
        val oversizedResponse = fullLengthResponse + byteArrayOf(0)

        val fakeUpstream = thread {
            val request = DatagramPacket(ByteArray(4096), 4096)
            server.receive(request)
            server.send(DatagramPacket(oversizedResponse, oversizedResponse.size, request.address, request.port))
        }

        try {
            assertNull(DnsUdpUpstreamClient.queryBlocking(client, query, loopback, server.localPort, 150))
            fakeUpstream.join(1000)
            assertTrue(!fakeUpstream.isAlive)
        } finally {
            client.close()
            server.close()
            fakeUpstream.join(1000)
        }
    }

    @Test
    fun rejectsUdpResponsesLargerThanTheRequestorsAdvertisedPayload() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query(edns = true, udpPayloadSize = 512)
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val oversizedResponse = DnsTestMessages.responseWithOptPadding(queryBytes, targetSize = 513, udpPayloadSize = 512)
        assertTrue(DnsMessageValidator.isValidResponse(oversizedResponse, query))

        val fakeUpstream = thread {
            val request = DatagramPacket(ByteArray(4096), 4096)
            server.receive(request)
            server.send(DatagramPacket(oversizedResponse, oversizedResponse.size, request.address, request.port))
        }

        try {
            assertNull(DnsUdpUpstreamClient.queryBlocking(client, query, loopback, server.localPort, 150))
            fakeUpstream.join(1000)
            assertTrue(!fakeUpstream.isAlive)
        } finally {
            client.close()
            server.close()
            fakeUpstream.join(1000)
        }
    }

    @Test
    fun invalidResponsesDoNotResetTheOriginalDeadline() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query

        val fakeUpstream = thread {
            val request = DatagramPacket(ByteArray(4096), 4096)
            server.receive(request)
            repeat(8) { index ->
                Thread.sleep(120)
                val invalid = DnsTestMessages.response(queryBytes, transactionId = 0x4000 + index)
                server.send(DatagramPacket(invalid, invalid.size, request.address, request.port))
            }
        }

        try {
            val startedAt = System.nanoTime()
            assertNull(DnsUdpUpstreamClient.queryBlocking(client, query, loopback, server.localPort, 400))
            val elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000L
            kotlin.test.assertTrue(elapsedMillis < 900, "invalid responses extended the deadline: ${elapsedMillis}ms")
            fakeUpstream.join(2000)
            assertTrue(!fakeUpstream.isAlive)
        } finally {
            client.close()
            server.close()
            fakeUpstream.join(2000)
        }
    }

    @Test
    fun cancellationClosesSocketAndStopsBlockingReceivePromptly() = runBlocking {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val requestReceived = CountDownLatch(1)
        val fakeUpstream = thread(name = "silent-dns-upstream") {
            runCatching {
                server.receive(DatagramPacket(ByteArray(4096), 4096))
                requestReceived.countDown()
            }
        }

        try {
            val request = async(Dispatchers.IO) {
                DnsUdpUpstreamClient.query(
                    socket = client,
                    query = query,
                    server = loopback,
                    port = server.localPort,
                    deadline = DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 3_000),
                    attemptTimeoutMillis = 3_000
                )
            }
            assertTrue(requestReceived.await(1, TimeUnit.SECONDS))
            val cancelledAt = System.nanoTime()
            request.cancelAndJoin()
            val elapsedMillis = (System.nanoTime() - cancelledAt) / 1_000_000L

            assertTrue(client.isClosed)
            assertTrue(elapsedMillis < 500, "socket receive continued for ${elapsedMillis}ms after cancellation")
            fakeUpstream.join(1_000)
            assertTrue(!fakeUpstream.isAlive)
        } finally {
            client.close()
            server.close()
            fakeUpstream.join(1_000)
        }
    }

    @Test
    fun doesNotSendUdpWhenIoDispatchConsumesTheRemainingDeadline() = runBlocking {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback).apply { soTimeout = 100 }
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val delayedDispatcher = QueuedDispatcher()

        try {
            val request = async(start = CoroutineStart.UNDISPATCHED) {
                DnsUdpUpstreamClient.query(
                    socket = client,
                    query = query,
                    server = loopback,
                    port = server.localPort,
                    deadline = DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 10),
                    attemptTimeoutMillis = 10,
                    ioDispatcher = delayedDispatcher
                )
            }
            Thread.sleep(25)
            delayedDispatcher.runPending()

            assertNull(request.await())
            val packet = DatagramPacket(ByteArray(4096), 4096)
            val receivedDatagram = runCatching {
                server.receive(packet)
                true
            }.getOrDefault(false)
            assertTrue(!receivedDatagram, "UDP query was sent after its deadline expired")
        } finally {
            client.close()
            server.close()
        }
    }

    @Test
    fun primaryUdpFailureFallsBackToSecondaryWithinTheSameDeadline() = runBlocking {
        val loopback = InetAddress.getByName("127.0.0.1")
        val primary = DatagramSocket(0, loopback)
        val secondary = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val expectedResponse = DnsTestMessages.response(queryBytes)
        val primaryReceived = CountDownLatch(1)
        val secondaryReceived = CountDownLatch(1)
        val udpAttempts = AtomicInteger()
        val udpRetries = AtomicInteger()
        val silentPrimary = thread(name = "silent-primary-dns") {
            runCatching {
                primary.receive(DatagramPacket(ByteArray(4096), 4096))
                primaryReceived.countDown()
            }
        }
        val respondingSecondary = thread(name = "secondary-dns") {
            val request = DatagramPacket(ByteArray(4096), 4096)
            secondary.receive(request)
            secondaryReceived.countDown()
            secondary.send(DatagramPacket(expectedResponse, expectedResponse.size, request.address, request.port))
        }

        try {
            val deadline = DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 1_000)
            val startedAt = System.nanoTime()
            val response = DnsUdpUpstreamClient.queryWithFallback(
                socket = client,
                query = query,
                upstreams = listOf(
                    DnsUdpUpstreamEndpoint(loopback, primary.localPort),
                    DnsUdpUpstreamEndpoint(loopback, secondary.localPort)
                ),
                deadline = deadline,
                onAttempt = { udpAttempts.incrementAndGet() },
                onRetry = { udpRetries.incrementAndGet() }
            )
            val elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000L

            assertContentEquals(expectedResponse, response)
            assertTrue(primaryReceived.await(1, TimeUnit.SECONDS))
            assertTrue(secondaryReceived.await(1, TimeUnit.SECONDS))
            assertEquals(2, udpAttempts.get())
            assertEquals(1, udpRetries.get())
            assertTrue(elapsedMillis < 1_000, "UDP fallback exceeded the total deadline: ${elapsedMillis}ms")
            respondingSecondary.join(1_000)
            assertTrue(!respondingSecondary.isAlive)
        } finally {
            client.close()
            primary.close()
            secondary.close()
            silentPrimary.join(1_000)
            respondingSecondary.join(1_000)
        }
    }
}
