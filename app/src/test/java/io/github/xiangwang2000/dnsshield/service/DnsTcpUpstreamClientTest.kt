package io.github.xiangwang2000.dnsshield.service

import java.io.DataInputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsTcpUpstreamClientTest {
    @Test
    fun framesQueryAndReadsPartialResponseLengthAndBody() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = ServerSocket(0, 1, loopback)
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val expected = DnsTestMessages.response(queryBytes)
        val upstreamQuery = AtomicReference<ByteArray?>()
        val serverFailure = AtomicReference<Throwable?>()
        val serverThread = thread(name = "partial-tcp-dns-upstream") {
            try {
                server.accept().use { connection ->
                    val input = DataInputStream(connection.getInputStream())
                    val queryLength = input.readUnsignedShort()
                    val receivedQuery = ByteArray(queryLength)
                    input.readFully(receivedQuery)
                    upstreamQuery.set(receivedQuery)

                    val output = connection.getOutputStream()
                    output.write((expected.size ushr 8) and 0xFF)
                    output.flush()
                    Thread.sleep(15)
                    output.write(expected.size and 0xFF)
                    output.flush()
                    Thread.sleep(15)
                    val split = expected.size / 2
                    output.write(expected, 0, split)
                    output.flush()
                    Thread.sleep(15)
                    output.write(expected, split, expected.size - split)
                    output.flush()
                }
            } catch (failure: Throwable) {
                serverFailure.set(failure)
            }
        }
        val client = Socket()
        val preparedBeforeConnect = AtomicBoolean(false)

        try {
            val response = DnsTcpUpstreamClient.queryBlocking(
                socket = client,
                query = query,
                server = loopback,
                port = server.localPort,
                timeoutMillis = 1_500,
                prepareSocket = { candidate ->
                    preparedBeforeConnect.set(!candidate.isConnected)
                    true
                }
            )

            assertContentEquals(expected, response)
            assertContentEquals(DnsMessageValidator.prepareUpstreamQuery(query), upstreamQuery.get())
            assertTrue(preparedBeforeConnect.get(), "the socket must be prepared before connect")
            serverThread.join(1_000)
            assertTrue(!serverThread.isAlive)
            assertNull(serverFailure.get())
        } finally {
            client.close()
            server.close()
            serverThread.join(1_000)
        }
    }

    @Test
    fun rejectsZeroShortAndOversizedTcpFramesBeforeReadingTheBody() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query

        listOf(0, 1, DnsMessageValidator.MAX_DNS_MESSAGE_BYTES + 1, 65_535).forEach { badLength ->
            val server = ServerSocket(0, 1, loopback)
            val serverThread = thread(name = "bad-tcp-dns-upstream-$badLength") {
                server.accept().use { connection ->
                    val input = DataInputStream(connection.getInputStream())
                    val queryLength = input.readUnsignedShort()
                    input.readFully(ByteArray(queryLength))
                    connection.getOutputStream().apply {
                        write(badLength ushr 8)
                        write(badLength and 0xFF)
                        flush()
                    }
                }
            }
            val client = Socket()
            try {
                assertNull(
                    DnsTcpUpstreamClient.queryBlocking(
                        socket = client,
                        query = query,
                        server = loopback,
                        port = server.localPort,
                        timeoutMillis = 500
                    ),
                    "DNS/TCP frame length $badLength must be rejected"
                )
                serverThread.join(1_000)
                assertTrue(!serverThread.isAlive)
            } finally {
                client.close()
                server.close()
                serverThread.join(1_000)
            }
        }
    }

    @Test
    fun returnsNullWhenTheResponseDoesNotArriveBeforeTheAttemptTimeout() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = ServerSocket(0, 1, loopback)
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val requestReceived = CountDownLatch(1)
        val serverThread = thread(name = "silent-tcp-dns-upstream") {
            server.accept().use { connection ->
                val input = DataInputStream(connection.getInputStream())
                val queryLength = input.readUnsignedShort()
                input.readFully(ByteArray(queryLength))
                requestReceived.countDown()
                Thread.sleep(350)
            }
        }
        val client = Socket()

        try {
            assertNull(
                DnsTcpUpstreamClient.queryBlocking(
                    socket = client,
                    query = query,
                    server = loopback,
                    port = server.localPort,
                    timeoutMillis = 100
                )
            )
            assertTrue(requestReceived.await(1, TimeUnit.SECONDS))
            serverThread.join(1_000)
            assertTrue(!serverThread.isAlive)
        } finally {
            client.close()
            server.close()
            serverThread.join(1_000)
        }
    }

    @Test
    fun cancellationClosesTheBlockingTcpSocket() = runBlocking {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = ServerSocket(0, 1, loopback)
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val requestReceived = CountDownLatch(1)
        val serverThread = thread(name = "cancelled-tcp-dns-upstream") {
            server.accept().use { connection ->
                val input = DataInputStream(connection.getInputStream())
                val queryLength = input.readUnsignedShort()
                input.readFully(ByteArray(queryLength))
                requestReceived.countDown()
                connection.getInputStream().read()
            }
        }
        val client = Socket()

        try {
            val request = async(Dispatchers.IO) {
                DnsTcpUpstreamClient.query(
                    socket = client,
                    query = query,
                    server = loopback,
                    port = server.localPort,
                    deadline = DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 3_000)
                )
            }
            assertTrue(requestReceived.await(1, TimeUnit.SECONDS))
            val cancelledAt = System.nanoTime()
            request.cancelAndJoin()
            val elapsedMillis = (System.nanoTime() - cancelledAt) / 1_000_000L

            assertTrue(client.isClosed)
            assertTrue(elapsedMillis < 500, "TCP read continued for ${elapsedMillis}ms after cancellation")
            serverThread.join(1_000)
            assertTrue(!serverThread.isAlive)
        } finally {
            client.close()
            server.close()
            serverThread.join(1_000)
        }
    }

    @Test
    fun requestDeadlineCancellationReleasesFencedFrameWriteForStrictActivation() = runBlocking {
        val loopback = InetAddress.getByName("127.0.0.1")
        val resolverId = 45
        val fence = DnsPlaintextFallbackFence()
        val frameWriteStarted = CountDownLatch(1)
        val frameWriteFinished = CountDownLatch(1)
        val socketClosed = CountDownLatch(1)
        val releaseFrameWrite = CountDownLatch(1)
        val closed = AtomicBoolean(false)
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val deadline = DnsRequestDeadline.fromReceivedAt(
            System.nanoTime(),
            timeoutMillis = 2_000
        )
        val client = object : Socket() {
            override fun connect(endpoint: SocketAddress?, timeout: Int) = Unit

            override fun isConnected(): Boolean = true

            override fun isClosed(): Boolean = closed.get()

            override fun close() {
                if (closed.compareAndSet(false, true)) {
                    socketClosed.countDown()
                    releaseFrameWrite.countDown()
                }
            }

            override fun getOutputStream(): OutputStream = object : OutputStream() {
                override fun write(value: Int) {
                    throw SocketException("DNS frame must use the byte-array write")
                }

                override fun write(bytes: ByteArray, offset: Int, length: Int) {
                    frameWriteStarted.countDown()
                    try {
                        if (!releaseFrameWrite.await(5, TimeUnit.SECONDS)) {
                            throw SocketException("Closing the socket did not release the DNS frame write")
                        }
                    } finally {
                        frameWriteFinished.countDown()
                    }
                }
            }
        }
        val request = async(Dispatchers.IO) {
            withTimeoutOrNull(deadline.remainingMillis()) {
                DnsTcpUpstreamClient.query(
                    socket = client,
                    query = query,
                    server = loopback,
                    deadline = deadline,
                    prepareSocket = { candidate ->
                        fence.registerTcpSocketIfAllowed(
                            resolverId,
                            snapshotAllowsPlaintext = true,
                            currentPolicyAllowsPlaintext = { true },
                            socket = candidate
                        )
                    },
                    sendQueryFrame = { candidate, frame ->
                        fence.writeTcpFrameIfAllowed(
                            resolverId,
                            snapshotAllowsPlaintext = true,
                            currentPolicyAllowsPlaintext = { true },
                            socket = candidate,
                            frame = frame
                        )
                    }
                )
            }
        }
        val setterAttempting = CountDownLatch(1)
        val setterReturned = CountDownLatch(1)
        val strictSetter = thread(start = false, name = "strict-policy-during-deadline-cancelled-write") {
            setterAttempting.countDown()
            fence.setAllowed(resolverId, false)
            setterReturned.countDown()
        }

        try {
            assertTrue(frameWriteStarted.await(1, TimeUnit.SECONDS), "the fenced DNS frame write did not start")
            strictSetter.start()
            assertTrue(setterAttempting.await(1, TimeUnit.SECONDS))

            val lockWaitDeadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
            while (strictSetter.state != Thread.State.BLOCKED && System.nanoTime() < lockWaitDeadlineNanos) {
                Thread.yield()
            }
            assertTrue(
                strictSetter.state == Thread.State.BLOCKED,
                "strict activation should wait for the in-flight fenced frame write"
            )

            assertTrue(
                socketClosed.await(3, TimeUnit.SECONDS),
                "request-deadline cancellation should close the socket while the fenced write is blocked"
            )
            assertTrue(frameWriteFinished.await(1, TimeUnit.SECONDS), "socket close did not release the fenced write")
            assertNull(request.await(), "the request deadline should cancel the upstream query")
            assertTrue(setterReturned.await(1, TimeUnit.SECONDS), "strict activation remained blocked after cancellation")
            assertTrue(client.isClosed)
            assertFalse(fence.allows(resolverId))
        } finally {
            client.close()
            request.cancelAndJoin()
            if (strictSetter.state == Thread.State.NEW) strictSetter.start()
            strictSetter.join(1_000)
            fence.unregisterTcpSocket(resolverId, client)
        }
        assertFalse(strictSetter.isAlive)
    }

    @Test
    fun strictActivationClosesARegisteredSocketDuringConnectWithoutHoldingTheFence() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val resolverId = 44
        val fence = DnsPlaintextFallbackFence()
        val connectStarted = CountDownLatch(1)
        val finishConnect = CountDownLatch(1)
        val frameWritten = AtomicBoolean(false)
        val connectFailure = AtomicReference<Throwable?>()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val client = object : Socket() {
            override fun connect(endpoint: SocketAddress?, timeout: Int) {
                connectStarted.countDown()
                check(finishConnect.await(5, TimeUnit.SECONDS))
                if (isClosed) throw SocketException("Socket closed while connecting")
            }

            override fun getOutputStream(): OutputStream = object : OutputStream() {
                override fun write(value: Int) {
                    frameWritten.set(true)
                }

                override fun write(bytes: ByteArray, offset: Int, length: Int) {
                    frameWritten.set(true)
                }
            }
        }
        val queryThread = thread(start = false, name = "policy-raced-tcp-query") {
            runCatching {
                DnsTcpUpstreamClient.queryBlocking(
                    socket = client,
                    query = query,
                    server = loopback,
                    timeoutMillis = 1_500,
                    prepareSocket = { candidate ->
                        assertFalse(candidate.isConnected)
                        fence.registerTcpSocketIfAllowed(
                            resolverId,
                            snapshotAllowsPlaintext = true,
                            currentPolicyAllowsPlaintext = { true },
                            socket = candidate
                        )
                    },
                    sendQueryFrame = { candidate, frame ->
                        fence.writeTcpFrameIfAllowed(
                            resolverId,
                            snapshotAllowsPlaintext = true,
                            currentPolicyAllowsPlaintext = { true },
                            socket = candidate,
                            frame = frame
                        )
                    }
                )
            }.exceptionOrNull()?.let(connectFailure::set)
        }
        val setterReturned = CountDownLatch(1)
        val strictSetter = thread(start = false, name = "strict-policy-during-tcp-connect") {
            fence.setAllowed(resolverId, false)
            setterReturned.countDown()
        }

        try {
            queryThread.start()
            assertTrue(connectStarted.await(1, TimeUnit.SECONDS))
            strictSetter.start()

            assertTrue(setterReturned.await(1, TimeUnit.SECONDS), "strict selection waited for TCP connect")
            assertTrue(client.isClosed)
            finishConnect.countDown()
            queryThread.join(1_000)
            strictSetter.join(1_000)

            assertTrue(!queryThread.isAlive)
            assertTrue(!strictSetter.isAlive)
            assertIs<SocketException>(connectFailure.get())
            assertFalse(frameWritten.get(), "a strict-policy TCP request frame must not be written")
        } finally {
            finishConnect.countDown()
            queryThread.join(1_000)
            strictSetter.join(1_000)
            fence.unregisterTcpSocket(resolverId, client)
            client.close()
        }
    }
}
