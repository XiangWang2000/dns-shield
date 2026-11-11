package io.github.xiangwang2000.dnsshield.service

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.io.DataInputStream
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
import kotlin.test.assertFalse
import kotlin.test.assertContentEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DnsUdpUpstreamClientTest {
    private fun countingReceiveBufferAllocator(allocations: AtomicInteger): (Int) -> ByteArray = { size ->
        assertEquals(DnsMessageValidator.MAX_UDP_RESPONSE_BYTES + 1, size)
        allocations.incrementAndGet()
        ByteArray(size)
    }

    private class QueuedDispatcher : CoroutineDispatcher() {
        private var pending: Runnable? = null

        override fun dispatch(context: CoroutineContext, block: Runnable) {
            pending = block
        }

        fun runPending() {
            checkNotNull(pending).run()
        }
    }

    private class LoopbackDnsResponder(name: String) : AutoCloseable {
        val responseFlags = AtomicInteger(0x8180)
        val extendedRcode = AtomicInteger(0)
        val requests = AtomicInteger()
        private val requestObserved = CountDownLatch(1)
        private val socket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        private val failure = AtomicReference<Throwable?>()
        val endpoint = DnsUdpUpstreamEndpoint(InetAddress.getByName("127.0.0.1"), socket.localPort)
        private val listener = thread(name = name, isDaemon = true) {
            while (!socket.isClosed) {
                try {
                    val request = DatagramPacket(ByteArray(4096), 4096)
                    socket.receive(request)
                    requests.incrementAndGet()
                    requestObserved.countDown()
                    val flags = responseFlags.get()
                    if (flags != NO_RESPONSE) {
                        val requestBytes = request.data.copyOfRange(request.offset, request.offset + request.length)
                        val extended = extendedRcode.get()
                        val response = if (extended != 0) {
                            DnsTestMessages.responseWithOpt(requestBytes, extended)
                        } else {
                            DnsTestMessages.response(requestBytes, flags = flags)
                        }
                        socket.send(DatagramPacket(response, response.size, request.address, request.port))
                    }
                } catch (exception: java.net.SocketException) {
                    if (!socket.isClosed) failure.compareAndSet(null, exception)
                    return@thread
                } catch (exception: Throwable) {
                    failure.compareAndSet(null, exception)
                    return@thread
                }
            }
        }

        fun assertNoFailure() = assertNull(failure.get())

        fun awaitRequest(timeout: Long, unit: TimeUnit): Boolean = requestObserved.await(timeout, unit)

        override fun close() {
            socket.close()
            listener.join(1_000)
        }

        private companion object {
            const val NO_RESPONSE = Int.MIN_VALUE
        }
    }

    private data class LoopbackSample(
        val elapsedMillis: Long,
        val attempts: Int,
        val primaryTimeouts: Int,
        val secondaryTimeouts: Int,
        val answers: Int,
        val deferredPrimary: Int,
        val failures: Int
    )

    private suspend fun runLoopbackSample(
        query: ParsedDnsQuery,
        primary: DnsUdpUpstreamEndpoint,
        secondary: DnsUdpUpstreamEndpoint,
        backoff: UdpPrimaryBackoff?
    ): LoopbackSample {
        val socket = DatagramSocket()
        val attempts = AtomicInteger()
        val primaryTimeouts = AtomicInteger()
        val secondaryTimeouts = AtomicInteger()
        val answers = AtomicInteger()
        val deferredPrimary = AtomicInteger()
        val startedAt = System.nanoTime()
        val outcome = try {
            DnsUdpUpstreamClient.queryWithFallback(
                socket = socket,
                query = query,
                upstreams = listOf(primary, secondary),
                deadline = DnsRequestDeadline.fromReceivedAt(startedAt, timeoutMillis = 400),
                onAttempt = { attempts.incrementAndGet() },
                primaryBackoff = backoff,
                onTimeout = { isPrimary ->
                    if (isPrimary) primaryTimeouts.incrementAndGet() else secondaryTimeouts.incrementAndGet()
                },
                onAnswer = { answers.incrementAndGet() },
                onPrimaryDeferred = { deferredPrimary.incrementAndGet() }
            )
        } finally {
            socket.close()
        }
        val elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000L
        val responseCode = outcome?.response?.let { DnsMessageValidator.validatedResponseCode(it, query) } ?: -1
        val failures = if (responseCode == 0 || responseCode == 3) 0 else 1
        return LoopbackSample(
            elapsedMillis,
            attempts.get(),
            primaryTimeouts.get(),
            secondaryTimeouts.get(),
            answers.get(),
            deferredPrimary.get(),
            failures
        )
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
    fun rejectsReceiveBufferSaturatedTcClearDatagramsInsteadOfForwardingThem() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query(edns = true, udpPayloadSize = DnsMessageValidator.MAX_UDP_RESPONSE_BYTES)
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val fullLengthResponse = DnsTestMessages.responseWithOptPadding(
            queryBytes,
            targetSize = DnsMessageValidator.MAX_UDP_RESPONSE_BYTES,
            udpPayloadSize = DnsMessageValidator.MAX_UDP_RESPONSE_BYTES
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
        val receiveBufferAllocations = AtomicInteger()
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
            val outcome = DnsUdpUpstreamClient.queryWithFallback(
                socket = client,
                query = query,
                upstreams = listOf(
                    DnsUdpUpstreamEndpoint(loopback, primary.localPort),
                    DnsUdpUpstreamEndpoint(loopback, secondary.localPort)
                ),
                deadline = deadline,
                onAttempt = { udpAttempts.incrementAndGet() },
                onRetry = { udpRetries.incrementAndGet() },
                receiveBufferAllocator = countingReceiveBufferAllocator(receiveBufferAllocations)
            )
            val elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000L

            assertContentEquals(expectedResponse, outcome?.response)
            assertSame(DnsTransport.PLAINTEXT_UDP, outcome?.transport)
            assertTrue(primaryReceived.await(1, TimeUnit.SECONDS))
            assertTrue(secondaryReceived.await(1, TimeUnit.SECONDS))
            assertEquals(2, udpAttempts.get())
            assertEquals(1, udpRetries.get())
            assertEquals(1, receiveBufferAllocations.get())
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

    @Test
    fun bothUdpAttemptsFailWithOneReceiveBufferAllocation() = runBlocking {
        val loopback = InetAddress.getByName("127.0.0.1")
        val primary = DatagramSocket(0, loopback)
        val secondary = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val requestsReceived = CountDownLatch(2)
        val serverFailure = AtomicReference<Throwable?>()
        val servers = listOf(primary, secondary)
        val listeners = servers.mapIndexed { index, server ->
            thread(name = "silent-fallback-$index") {
                try {
                    server.receive(DatagramPacket(ByteArray(4096), 4096))
                    requestsReceived.countDown()
                } catch (failure: Throwable) {
                    serverFailure.compareAndSet(null, failure)
                }
            }
        }
        val allocations = AtomicInteger()

        try {
            val result = DnsUdpUpstreamClient.queryWithFallback(
                socket = client,
                query = query,
                upstreams = listOf(
                    DnsUdpUpstreamEndpoint(loopback, primary.localPort),
                    DnsUdpUpstreamEndpoint(loopback, secondary.localPort)
                ),
                deadline = DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 1_200),
                receiveBufferAllocator = countingReceiveBufferAllocator(allocations)
            )

            assertNull(result)
            assertTrue(requestsReceived.await(1, TimeUnit.SECONDS))
            assertEquals(1, allocations.get())
            listeners.forEach { it.join(1_000) }
            assertTrue(listeners.none { it.isAlive })
            assertNull(serverFailure.get())
        } finally {
            client.close()
            primary.close()
            secondary.close()
            listeners.forEach { it.join(1_000) }
        }
    }

    @Test
    fun concurrentFallbackQueriesUseIndependentReceiveBuffers() = runBlocking {
        val loopback = InetAddress.getByName("127.0.0.1")
        val servers = List(2) { DatagramSocket(0, loopback) }
        val clients = List(2) { DatagramSocket() }
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val expectedResponse = DnsTestMessages.response(queryBytes)
        val requestsReceived = CountDownLatch(2)
        val responsesReleased = CountDownLatch(1)
        val allocationsObserved = CountDownLatch(2)
        val allocatedBuffers = Array(2) { AtomicReference<ByteArray?>() }
        val allocationCounts = Array(2) { AtomicInteger() }
        val serverFailure = AtomicReference<Throwable?>()
        val responders = servers.mapIndexed { index, server ->
            thread(name = "concurrent-dns-$index") {
                try {
                    val request = DatagramPacket(ByteArray(4096), 4096)
                    server.receive(request)
                    requestsReceived.countDown()
                    check(responsesReleased.await(2, TimeUnit.SECONDS))
                    server.send(
                        DatagramPacket(expectedResponse, expectedResponse.size, request.address, request.port)
                    )
                } catch (failure: Throwable) {
                    serverFailure.compareAndSet(null, failure)
                }
            }
        }
        val queries = clients.mapIndexed { index, client ->
            async(Dispatchers.IO) {
                DnsUdpUpstreamClient.queryWithFallback(
                    socket = client,
                    query = query,
                    upstreams = listOf(DnsUdpUpstreamEndpoint(loopback, servers[index].localPort)),
                    deadline = DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 3_000),
                    receiveBufferAllocator = { size ->
                        allocationCounts[index].incrementAndGet()
                        ByteArray(size).also {
                            allocatedBuffers[index].set(it)
                            allocationsObserved.countDown()
                        }
                    }
                )
            }
        }

        try {
            assertTrue(requestsReceived.await(1, TimeUnit.SECONDS))
            assertTrue(allocationsObserved.await(1, TimeUnit.SECONDS))
            assertEquals(1, allocationCounts[0].get())
            assertEquals(1, allocationCounts[1].get())
            val firstBuffer = checkNotNull(allocatedBuffers[0].get())
            val secondBuffer = checkNotNull(allocatedBuffers[1].get())
            assertTrue(firstBuffer !== secondBuffer)
            assertEquals(DnsMessageValidator.MAX_UDP_RESPONSE_BYTES + 1, firstBuffer.size)
            assertEquals(DnsMessageValidator.MAX_UDP_RESPONSE_BYTES + 1, secondBuffer.size)

            responsesReleased.countDown()
            val outcomes = queries.map { it.await() }
            outcomes.forEach { assertContentEquals(expectedResponse, it?.response) }
            assertNull(serverFailure.get())
        } finally {
            responsesReleased.countDown()
            queries.forEach { it.cancel() }
            clients.forEach { it.close() }
            servers.forEach { it.close() }
            responders.forEach { it.join(1_000) }
        }
    }

    @Test
    fun reusedFallbackBufferDoesNotMutateEarlierTruncatedResponse() = runBlocking {
        val loopback = InetAddress.getByName("127.0.0.1")
        val primary = DatagramSocket(0, loopback)
        val secondary = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val truncatedResponse = DnsTestMessages.response(queryBytes, flags = 0x8380)
        val malformedResponse = byteArrayOf(0x12, 0x34)
        val secondaryReceived = CountDownLatch(1)
        val serverFailure = AtomicReference<Throwable?>()
        val primaryResponder = thread(name = "truncated-primary-dns") {
            try {
                val request = DatagramPacket(ByteArray(4096), 4096)
                primary.receive(request)
                primary.send(
                    DatagramPacket(truncatedResponse, truncatedResponse.size, request.address, request.port)
                )
            } catch (failure: Throwable) {
                serverFailure.compareAndSet(null, failure)
            }
        }
        val secondaryResponder = thread(name = "malformed-secondary-dns") {
            try {
                val request = DatagramPacket(ByteArray(4096), 4096)
                secondary.receive(request)
                secondaryReceived.countDown()
                secondary.send(
                    DatagramPacket(malformedResponse, malformedResponse.size, request.address, request.port)
                )
            } catch (failure: Throwable) {
                serverFailure.compareAndSet(null, failure)
            }
        }
        val allocations = AtomicInteger()

        try {
            val outcome = DnsUdpUpstreamClient.queryWithFallback(
                socket = client,
                query = query,
                upstreams = listOf(
                    DnsUdpUpstreamEndpoint(loopback, primary.localPort),
                    DnsUdpUpstreamEndpoint(loopback, secondary.localPort)
                ),
                deadline = DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 1_000),
                tcpQuery = { null },
                receiveBufferAllocator = countingReceiveBufferAllocator(allocations)
            )

            assertContentEquals(truncatedResponse, outcome?.response)
            assertSame(DnsTransport.PLAINTEXT_UDP, outcome?.transport)
            assertTrue(secondaryReceived.await(1, TimeUnit.SECONDS))
            assertEquals(1, allocations.get())
            assertNull(serverFailure.get())
        } finally {
            client.close()
            primary.close()
            secondary.close()
            primaryResponder.join(1_000)
            secondaryResponder.join(1_000)
        }
    }

    private fun bindDualProtocolServers(loopback: InetAddress): Pair<DatagramSocket, ServerSocket> {
        // Reserve UDP first: Windows may allow TCP to select a port excluded from UDP binding.
        var lastFailure: java.net.BindException? = null
        var lastPort = 0
        repeat(20) {
            val udpServer = DatagramSocket(0, loopback)
            try {
                return udpServer to ServerSocket(udpServer.localPort, 1, loopback)
            } catch (failure: java.net.BindException) {
                lastPort = udpServer.localPort
                lastFailure = failure
                udpServer.close()
            } catch (failure: Exception) {
                udpServer.close()
                throw failure
            }
        }
        throw java.net.BindException("Could not reserve UDP/TCP loopback sockets; last port=$lastPort")
            .apply { initCause(lastFailure) }
    }

    @Test
    fun truncatedUdpResponseRetriesTheSameUpstreamOverTcpWithinTheDeadline() = runBlocking {
        val loopback = InetAddress.getByName("127.0.0.1")
        val (udpServer, tcpServer) = bindDualProtocolServers(loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val truncatedResponse = DnsTestMessages.response(queryBytes, flags = 0x8380).also {
            it[7] = 1 // TC responses may end partway through the answer section.
        }
        val fullResponse = DnsTestMessages.response(queryBytes)
        val serverFailure = AtomicReference<Throwable?>()
        val udpResponder = thread(name = "tc-udp-upstream") {
            try {
                val request = DatagramPacket(ByteArray(4096), 4096)
                udpServer.receive(request)
                udpServer.send(
                    DatagramPacket(truncatedResponse, truncatedResponse.size, request.address, request.port)
                )
            } catch (failure: Throwable) {
                serverFailure.compareAndSet(null, failure)
            }
        }
        val tcpResponder = thread(name = "tc-tcp-upstream") {
            try {
                tcpServer.accept().use { connection ->
                    val input = DataInputStream(connection.getInputStream())
                    val queryLength = input.readUnsignedShort()
                    val upstreamQuery = ByteArray(queryLength)
                    input.readFully(upstreamQuery)
                    if (!upstreamQuery.contentEquals(DnsMessageValidator.prepareUpstreamQuery(query))) {
                        error("TCP fallback query frame did not match the DNS query")
                    }
                    val frame = ByteArray(fullResponse.size + 2)
                    frame[0] = (fullResponse.size ushr 8).toByte()
                    frame[1] = fullResponse.size.toByte()
                    System.arraycopy(fullResponse, 0, frame, 2, fullResponse.size)
                    connection.getOutputStream().write(frame)
                    connection.getOutputStream().flush()
                }
            } catch (failure: Throwable) {
                serverFailure.compareAndSet(null, failure)
            }
        }

        try {
            val deadline = DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 1_500)
            val outcome = DnsUdpUpstreamClient.queryWithFallback(
                socket = client,
                query = query,
                upstreams = listOf(DnsUdpUpstreamEndpoint(loopback, udpServer.localPort)),
                deadline = deadline,
                tcpQuery = { upstream ->
                    val tcpClient = Socket()
                    try {
                        DnsTcpUpstreamClient.query(
                            socket = tcpClient,
                            query = query,
                            server = upstream.address,
                            port = upstream.port,
                            deadline = deadline
                        )
                    } finally {
                        tcpClient.close()
                    }
                }
            )

            assertContentEquals(fullResponse, assertNotNull(outcome).response)
            assertSame(DnsTransport.PLAINTEXT_TCP, outcome.transport)
            udpResponder.join(1_000)
            tcpResponder.join(1_000)
            assertNull(serverFailure.get())
        } finally {
            client.close()
            udpServer.close()
            tcpServer.close()
            udpResponder.join(1_000)
            tcpResponder.join(1_000)
        }
    }

    @Test
    fun adaptiveFallbackRequiresUsableBackupAndRecoversWhenBackupDisappears() = runBlocking {
        var monotonicMillis = 1_000L
        val backoff = UdpPrimaryBackoff(monotonicMillis = { monotonicMillis })
        val primaryServer = LoopbackDnsResponder("adaptive-primary")
        val secondaryServer = LoopbackDnsResponder("adaptive-secondary")
        val queryBytes = DnsTestMessages.query(edns = true)
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        primaryServer.responseFlags.set(Int.MIN_VALUE)

        try {
            secondaryServer.extendedRcode.set(1)
            repeat(2) {
                val unusableBackup = runLoopbackSample(
                    query,
                    primaryServer.endpoint,
                    secondaryServer.endpoint,
                    backoff
                )
                assertEquals(2, unusableBackup.attempts)
                assertEquals(1, unusableBackup.primaryTimeouts)
                assertEquals(1, unusableBackup.answers)
                assertEquals(1, unusableBackup.failures)
                assertEquals(0, unusableBackup.deferredPrimary)
            }

            val stillPrimaryFirst = runLoopbackSample(
                query,
                primaryServer.endpoint,
                secondaryServer.endpoint,
                backoff
            )
            assertEquals(2, stillPrimaryFirst.attempts)
            assertEquals(0, stillPrimaryFirst.deferredPrimary)

            secondaryServer.extendedRcode.set(0)
            repeat(2) {
                val usableBackup = runLoopbackSample(
                    query,
                    primaryServer.endpoint,
                    secondaryServer.endpoint,
                    backoff
                )
                assertEquals(2, usableBackup.attempts)
                assertEquals(0, usableBackup.failures)
                assertEquals(0, usableBackup.deferredPrimary)
            }

            val preferredBackup = runLoopbackSample(
                query,
                primaryServer.endpoint,
                secondaryServer.endpoint,
                backoff
            )
            assertEquals(1, preferredBackup.attempts)
            assertEquals(1, preferredBackup.deferredPrimary)
            assertEquals(0, preferredBackup.failures)

            secondaryServer.responseFlags.set(0x8182)
            primaryServer.responseFlags.set(Int.MIN_VALUE)
            val retainedBackupError = runLoopbackSample(
                query,
                primaryServer.endpoint,
                secondaryServer.endpoint,
                backoff
            )
            assertEquals(2, retainedBackupError.attempts)
            assertEquals(1, retainedBackupError.answers)
            assertEquals(1, retainedBackupError.failures)

            primaryServer.responseFlags.set(0x8180)
            val primaryRecoversFromBackupError = runLoopbackSample(
                query,
                primaryServer.endpoint,
                secondaryServer.endpoint,
                backoff
            )
            assertEquals(2, primaryRecoversFromBackupError.attempts)
            assertEquals(2, primaryRecoversFromBackupError.answers)
            assertEquals(1, primaryRecoversFromBackupError.deferredPrimary)
            assertEquals(0, primaryRecoversFromBackupError.failures)

            primaryServer.responseFlags.set(Int.MIN_VALUE)
            secondaryServer.responseFlags.set(0x8180)
            repeat(2) {
                val requalified = runLoopbackSample(
                    query,
                    primaryServer.endpoint,
                    secondaryServer.endpoint,
                    backoff
                )
                assertEquals(2, requalified.attempts)
                assertEquals(0, requalified.failures)
            }

            secondaryServer.responseFlags.set(Int.MIN_VALUE)
            primaryServer.responseFlags.set(0x8180)
            val fallbackToRecoveredPrimary = runLoopbackSample(
                query,
                primaryServer.endpoint,
                secondaryServer.endpoint,
                backoff
            )
            assertEquals(2, fallbackToRecoveredPrimary.attempts)
            assertEquals(0, fallbackToRecoveredPrimary.primaryTimeouts)
            assertEquals(1, fallbackToRecoveredPrimary.secondaryTimeouts)
            assertEquals(0, fallbackToRecoveredPrimary.failures)

            val recoveredPrimaryFirst = runLoopbackSample(
                query,
                primaryServer.endpoint,
                secondaryServer.endpoint,
                backoff
            )
            assertEquals(1, recoveredPrimaryFirst.attempts)
            assertEquals(0, recoveredPrimaryFirst.failures)

            System.out.println(
                "udp backoff loopback: unusable backup remained primary-first; healthy backup used " +
                    "${preferredBackup.attempts} attempt; after backup loss primary recovered in " +
                    "${fallbackToRecoveredPrimary.elapsedMillis}ms"
            )
        } finally {
            primaryServer.close()
            secondaryServer.close()
        }

        primaryServer.assertNoFailure()
        secondaryServer.assertNoFailure()
    }

    @Test
    fun cancellingExpiredCooldownProbeReleasesItsSingleProbeSlot() = runBlocking {
        var monotonicMillis = 1_000L
        val backoff = UdpPrimaryBackoff(monotonicMillis = { monotonicMillis })
        val primaryServer = LoopbackDnsResponder("cancelled-primary-probe")
        val secondaryServer = LoopbackDnsResponder("cancelled-secondary-probe")
        val primary = primaryServer.endpoint
        val secondary = secondaryServer.endpoint
        val socket = DatagramSocket()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val probeObserved = CountDownLatch(1)
        primaryServer.responseFlags.set(Int.MIN_VALUE)

        try {
            repeat(2) {
                val permit = backoff.beginQuery(primary, secondary)
                backoff.finishQuery(
                    permit = permit,
                    primaryAttempted = true,
                    primaryTimedOut = true,
                    primaryResponded = false,
                    primarySucceeded = false,
                    backupSucceeded = true
                )
            }
            monotonicMillis += 15_000L

            val request = async(Dispatchers.IO) {
                DnsUdpUpstreamClient.queryWithFallback(
                    socket = socket,
                    query = query,
                    upstreams = listOf(primary, secondary),
                    deadline = DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 3_000),
                    primaryBackoff = backoff,
                    onAttempt = { probeObserved.countDown() }
                )
            }
            assertTrue(probeObserved.await(1, TimeUnit.SECONDS))
            assertTrue(primaryServer.awaitRequest(1, TimeUnit.SECONDS))
            request.cancelAndJoin()

            assertTrue(socket.isClosed)
            val afterCancellation = backoff.beginQuery(primary, secondary)
            assertFalse(afterCancellation.preferBackup)
            backoff.abandonQuery(afterCancellation)
            assertEquals(0, secondaryServer.requests.get())
        } finally {
            socket.close()
            primaryServer.close()
            secondaryServer.close()
        }

        primaryServer.assertNoFailure()
        secondaryServer.assertNoFailure()
    }
}
