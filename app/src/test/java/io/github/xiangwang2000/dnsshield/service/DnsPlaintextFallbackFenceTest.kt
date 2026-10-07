package io.github.xiangwang2000.dnsshield.service

import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsPlaintextFallbackFenceTest {
    @Test
    fun strictRequestAndFailedWriteCannotBeOverriddenByAnOldRow() {
        val fence = DnsPlaintextFallbackFence()

        assertTrue(fence.requestPolicy(1, 1, false))
        assertFalse(fence.markPersisted(1, 1, true))
        assertFalse(fence.applyStoredPolicy(1, 2, true))
        assertFalse(fence.allows(1))

        assertTrue(fence.markPersisted(1, 1, false))
        assertTrue(fence.applyStoredPolicy(1, 2, false))
        assertFalse(fence.applyStoredPolicy(1, 3, true))
        assertFalse(fence.requestPolicy(1, 1, true))
        assertFalse(fence.allows(1))

        assertTrue(fence.requestPolicy(1, 4, true))
        assertFalse(fence.allows(1), "ALLOW stays pending until it is saved and applied")
        assertTrue(fence.markPersisted(1, 4, true))
        assertTrue(fence.applyStoredPolicy(1, 5, true))
        assertTrue(fence.allows(1))
    }

    @Test
    fun pendingAllowAndStaleDatabaseReadKeepStrictFenceClosed() {
        val resolverId = 45
        val fence = DnsPlaintextFallbackFence()

        assertTrue(fence.requestPolicy(resolverId, 1, false))
        assertTrue(fence.markPersisted(resolverId, 1, false))
        assertTrue(fence.applyStoredPolicy(resolverId, 1, false))
        assertTrue(fence.requestPolicy(resolverId, 2, true))

        assertFalse(fence.applyStoredPolicy(resolverId, 3, true), "A stale allow=true row cannot win")
        assertFalse(fence.allows(resolverId))
    }

    @Test
    fun rebuiltFenceInitializesFromPersistedActiveRow() {
        val resolverId = 46
        val rebuilt = DnsPlaintextFallbackFence()

        assertTrue(rebuilt.applyStoredPolicy(resolverId, 7, false))
        assertFalse(rebuilt.allows(resolverId))
    }

    @Test
    fun strictSelectionClosesRegisteredTcpSocketBeforeConnect() {
        val resolverId = 42
        val fence = DnsPlaintextFallbackFence()
        val socket = Socket()
        val strictSocket = Socket()

        try {
            assertTrue(fence.registerTcpSocketIfAllowed(resolverId, true, { true }, socket))
            assertTrue(fence.requestPolicy(resolverId, 42, false))
            assertTrue(fence.markPersisted(resolverId, 42, false))
            assertTrue(fence.applyStoredPolicy(resolverId, 42, false))
            fence.closeSocketsIfStillStrict(resolverId, 42)

            assertTrue(socket.isClosed)
            assertFalse(socket.isConnected)
            assertFalse(
                fence.registerTcpSocketIfAllowed(
                    resolverId,
                    snapshotAllowsPlaintext = true,
                    currentPolicyAllowsPlaintext = { true },
                    socket = strictSocket
                )
            )
        } finally {
            fence.unregisterTcpSocket(resolverId, socket)
            socket.close()
            strictSocket.close()
        }
    }

    @Test
    fun strictPublicationAndTcpCleanupDoNotWaitForAnInflightWrite() {
        val resolverId = 43
        val fence = DnsPlaintextFallbackFence()
        val writeStarted = CountDownLatch(1)
        val allowWriteToFinish = CountDownLatch(1)
        val frameWritten = AtomicReference<ByteArray?>()
        val writeFailure = AtomicReference<Throwable?>()
        val closed = AtomicBoolean(false)
        val query = DnsTestMessages.query()
        val frame = ByteArray(query.size + 2).also {
            it[0] = (query.size ushr 8).toByte()
            it[1] = query.size.toByte()
            System.arraycopy(query, 0, it, 2, query.size)
        }
        val socket = object : Socket() {
            override fun getOutputStream(): OutputStream = object : OutputStream() {
                override fun write(value: Int) = write(byteArrayOf(value.toByte()))

                override fun write(bytes: ByteArray, offset: Int, length: Int) {
                    writeStarted.countDown()
                    check(allowWriteToFinish.await(5, TimeUnit.SECONDS))
                    if (closed.get()) throw SocketException("strict policy closed the socket")
                    frameWritten.set(bytes.copyOfRange(offset, offset + length))
                }
            }

            override fun close() {
                closed.set(true)
                allowWriteToFinish.countDown()
                super.close()
            }
        }
        val writer = Thread {
            try {
                fence.writeTcpFrameIfAllowed(
                    resolverId,
                    snapshotAllowsPlaintext = true,
                    currentPolicyAllowsPlaintext = { true },
                    socket = socket,
                    frame = frame
                )
            } catch (failure: Throwable) {
                writeFailure.set(failure)
            }
        }
        val publicationReturned = CountDownLatch(1)
        val cleanupReturned = CountDownLatch(1)
        val strictSetter = Thread {
            fence.requestPolicy(resolverId, 44, false)
            publicationReturned.countDown()
            fence.closeSocketsIfStillStrict(resolverId, 44)
            cleanupReturned.countDown()
        }

        try {
            assertTrue(fence.registerTcpSocketIfAllowed(resolverId, true, { true }, socket))
            writer.start()
            assertTrue(writeStarted.await(1, TimeUnit.SECONDS))
            strictSetter.start()

            assertTrue(publicationReturned.await(1, TimeUnit.SECONDS))
            assertTrue(cleanupReturned.await(1, TimeUnit.SECONDS))
            assertFalse(fence.allows(resolverId))
            writer.join(1_000)
            assertFalse(writer.isAlive)
            assertTrue(socket.isClosed)
            assertNull(frameWritten.get(), "Closing a registered TCP socket interrupts the in-flight write")
            assertIs<SocketException>(writeFailure.get())

            assertFalse(
                fence.writeTcpFrameIfAllowed(
                    resolverId,
                    snapshotAllowsPlaintext = true,
                    currentPolicyAllowsPlaintext = { true },
                    socket = socket,
                    frame = frame
                )
            )
            assertNull(frameWritten.get())
        } finally {
            allowWriteToFinish.countDown()
            strictSetter.join(1_000)
            writer.join(1_000)
            fence.unregisterTcpSocket(resolverId, socket)
            socket.close()
        }
    }

    @Test
    fun oldStrictCleanupDoesNotCloseSocketReusedAfterNewAllow() {
        val resolverId = 44
        val fence = DnsPlaintextFallbackFence()
        val socket = Socket()

        try {
            assertTrue(fence.registerTcpSocketIfAllowed(resolverId, true, { true }, socket))
            assertTrue(fence.requestPolicy(resolverId, 1, false))
            assertTrue(fence.markPersisted(resolverId, 1, false))
            assertTrue(fence.requestPolicy(resolverId, 2, true))
            assertTrue(fence.markPersisted(resolverId, 2, true))
            assertTrue(fence.applyStoredPolicy(resolverId, 2, true))
            assertTrue(fence.registerTcpSocketIfAllowed(resolverId, true, { true }, socket))

            fence.closeSocketsIfStillStrict(resolverId, 1)

            assertFalse(socket.isClosed)
        } finally {
            fence.unregisterTcpSocket(resolverId, socket)
            socket.close()
        }
    }

    @Test
    fun strictSelectionBlocksPendingUdpSend() {
        val resolverId = 41
        val fence = DnsPlaintextFallbackFence()
        val receiver = DatagramSocket(0).apply { soTimeout = 200 }
        val socket = PolicyFencedDatagramSocket(
            resolverId = resolverId,
            snapshotAllowsPlaintext = true,
            fence = fence,
            currentPolicyAllowsPlaintext = { true }
        )
        val sendReady = CountDownLatch(1)
        val continueSend = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        val sender = Thread {
            sendReady.countDown()
            try {
                check(continueSend.await(5, TimeUnit.SECONDS))
                socket.send(
                    DatagramPacket(
                        byteArrayOf(1),
                        1,
                        InetAddress.getByName("127.0.0.1"),
                        receiver.localPort
                    )
                )
            } catch (exception: Throwable) {
                failure.set(exception)
            }
        }

        try {
            sender.start()
            assertTrue(sendReady.await(5, TimeUnit.SECONDS))
            assertTrue(fence.requestPolicy(resolverId, 1, false))
            continueSend.countDown()
            sender.join(5_000)

            assertFalse(sender.isAlive)
            assertIs<SocketException>(failure.get())
            assertTrue(
                runCatching {
                    receiver.receive(DatagramPacket(ByteArray(8), 8))
                }.exceptionOrNull() is SocketTimeoutException
            )
        } finally {
            continueSend.countDown()
            socket.close()
            receiver.close()
            sender.join(5_000)
        }
    }
}
