package io.github.xiangwang2000.dnsshield.service

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class VpnTunnelIoTest {
    @Test
    fun nullEstablishResultInvokesUnavailableHandler() {
        var establishCalls = 0
        var unavailable = false

        val descriptor = establishVpnTunnel(
            establish = {
                establishCalls++
                null
            },
            onUnavailable = { unavailable = true }
        )

        assertNull(descriptor)
        assertEquals(1, establishCalls)
        assertTrue(unavailable)
    }

    @Test
    fun unexpectedEofClosesBothStreamsAndReportsTunnelFailure() {
        val input = TrackingInputStream(ByteArrayInputStream(ByteArray(0)))
        val output = TrackingOutputStream()
        val failures = mutableListOf<String?>()

        runVpnTunnelReader(
            openInput = { input },
            openOutput = { output },
            isActive = { true },
            handlePacket = { _, _, _ -> error("EOF must not produce a packet") },
            onEnded = { failures.add(it) }
        )

        assertEquals(listOf<String?>("Tunnel stream reached EOF unexpectedly"), failures)
        assertTrue(input.closed)
        assertTrue(output.closed)
    }

    @Test
    fun eofAfterStopDoesNotReportUnexpectedTunnelFailure() {
        val active = AtomicBoolean(true)
        val input = object : InputStream() {
            var closed = false
                private set

            override fun read(): Int = -1

            override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
                active.set(false)
                return -1
            }

            override fun close() {
                closed = true
            }
        }
        val output = TrackingOutputStream()
        val failures = mutableListOf<String?>()

        runVpnTunnelReader(
            openInput = { input },
            openOutput = { output },
            isActive = active::get,
            handlePacket = { _, _, _ -> error("EOF must not produce a packet") },
            onEnded = { failures.add(it) }
        )

        assertEquals(listOf<String?>(null), failures)
        assertTrue(input.closed)
        assertTrue(output.closed)
    }

    @Test
    fun readFailureClosesBothStreamsAndReportsTheReadError() {
        val input = FailingInputStream(IOException("synthetic read failure"))
        val output = TrackingOutputStream()
        val failures = mutableListOf<String?>()

        runVpnTunnelReader(
            openInput = { input },
            openOutput = { output },
            isActive = { true },
            handlePacket = { _, _, _ -> error("A failed read must not produce a packet") },
            onEnded = { failures.add(it) }
        )

        assertEquals(listOf<String?>("Tunnel read error: synthetic read failure"), failures)
        assertTrue(input.closed)
        assertTrue(output.closed)
    }

    @Test
    fun stoppingBlockedReaderClosesDescriptorBeforeJoiningAndSuppressesFailure() = runBlocking {
        val active = AtomicBoolean(true)
        val input = BlockingInputStream()
        val output = TrackingOutputStream()
        val ended = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val failures = mutableListOf<String?>()
        var readerException: Throwable? = null
        val reader = Thread {
            try {
                runVpnTunnelReader(
                    openInput = { input },
                    openOutput = { output },
                    isActive = active::get,
                    handlePacket = { _, _, _ -> error("Blocked read must not produce a packet") },
                    onEnded = {
                        synchronized(failures) { failures.add(it) }
                        ended.countDown()
                    }
                )
            } catch (exception: Throwable) {
                readerException = exception
            } finally {
                finished.countDown()
            }
        }.apply {
            name = "vpn-tunnel-reader-test"
            isDaemon = true
            start()
        }

        assertTrue(input.readStarted.await(1, TimeUnit.SECONDS), "Reader did not enter its blocking read")

        closeVpnTunnelThenJoin(
            closeDescriptor = {
                active.set(false)
                input.close()
            },
            joinSession = {
                reader.join(1_000)
                assertFalse(reader.isAlive, "Reader remained blocked after descriptor close")
            },
            onCloseFailure = { throw it },
            onJoinFailure = { throw it }
        )

        assertTrue(finished.await(0, TimeUnit.SECONDS))
        assertTrue(ended.await(0, TimeUnit.SECONDS))
        assertNull(readerException)
        assertEquals(listOf(null), synchronized(failures) { failures.toList() })
        assertTrue(input.closed)
        assertTrue(output.closed)
    }

    private class TrackingInputStream(
        private val delegate: InputStream
    ) : InputStream() {
        var closed = false
            private set

        override fun read(): Int = delegate.read()

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int =
            delegate.read(buffer, offset, length)

        override fun close() {
            closed = true
            delegate.close()
        }
    }

    private class FailingInputStream(
        private val failure: IOException
    ) : InputStream() {
        var closed = false
            private set

        override fun read(): Int = throw failure

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int = throw failure

        override fun close() {
            closed = true
        }
    }

    private class BlockingInputStream : InputStream() {
        val readStarted = CountDownLatch(1)
        private val closedLatch = CountDownLatch(1)

        @Volatile
        var closed = false
            private set

        override fun read(): Int = error("Byte-array read is expected")

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            readStarted.countDown()
            closedLatch.await()
            throw IOException("descriptor closed")
        }

        override fun close() {
            closed = true
            closedLatch.countDown()
        }
    }

    private class TrackingOutputStream : OutputStream() {
        var closed = false
            private set

        override fun write(value: Int) = Unit

        override fun close() {
            closed = true
        }
    }
}
