package io.github.xiangwang2000.dnsshield.service

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DnsPlaintextFallbackFenceTest {
    @Test
    fun strictSelectionClosesRegisteredTcpSocketBeforeConnect() {
        val resolverId = 42
        val fence = DnsPlaintextFallbackFence()
        val socket = Socket()
        val strictSocket = Socket()

        try {
            assertTrue(
                fence.registerTcpSocketIfAllowed(
                    resolverId,
                    snapshotAllowsPlaintext = true,
                    currentPolicyAllowsPlaintext = { true },
                    socket = socket
                )
            )
            fence.setAllowed(resolverId, false)

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
    fun strictSelectionSerializesAgainstTheDnsTcpRequestFrameWrite() {
        val resolverId = 43
        val fence = DnsPlaintextFallbackFence()
        val writeStarted = CountDownLatch(1)
        val allowWriteToFinish = CountDownLatch(1)
        val frameWritten = AtomicReference<ByteArray?>()
        val writeFailure = AtomicReference<Throwable?>()
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
                    frameWritten.set(bytes.copyOfRange(offset, offset + length))
                }
            }
        }
        val writer = Thread {
            try {
                check(
                    fence.writeTcpFrameIfAllowed(
                        resolverId,
                        snapshotAllowsPlaintext = true,
                        currentPolicyAllowsPlaintext = { true },
                        socket = socket,
                        frame = frame
                    )
                )
            } catch (failure: Throwable) {
                writeFailure.set(failure)
            }
        }
        val setterStarted = CountDownLatch(1)
        val setterReturned = CountDownLatch(1)
        val strictSetter = Thread {
            setterStarted.countDown()
            fence.setAllowed(resolverId, false)
            setterReturned.countDown()
        }

        try {
            assertTrue(
                fence.registerTcpSocketIfAllowed(
                    resolverId,
                    snapshotAllowsPlaintext = true,
                    currentPolicyAllowsPlaintext = { true },
                    socket = socket
                )
            )
            writer.start()
            assertTrue(writeStarted.await(1, TimeUnit.SECONDS))
            strictSetter.start()
            assertTrue(setterStarted.await(1, TimeUnit.SECONDS))
            assertFalse(setterReturned.await(100, TimeUnit.MILLISECONDS))
            allowWriteToFinish.countDown()
            writer.join(1_000)
            strictSetter.join(1_000)

            assertFalse(writer.isAlive)
            assertFalse(strictSetter.isAlive)
            assertTrue(setterReturned.count == 0L)
            assertContentEquals(frame, frameWritten.get())
            assertFalse(
                fence.writeTcpFrameIfAllowed(
                    resolverId,
                    snapshotAllowsPlaintext = true,
                    currentPolicyAllowsPlaintext = { true },
                    socket = socket,
                    frame = frame
                )
            )
            assertTrue(frameWritten.get()!!.contentEquals(frame))
            kotlin.test.assertNull(writeFailure.get())
        } finally {
            allowWriteToFinish.countDown()
            strictSetter.join(1_000)
            writer.join(1_000)
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
            fence.setAllowed(resolverId, false)
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
