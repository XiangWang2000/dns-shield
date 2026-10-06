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
    fun outputLifecycleClosesNativeOwnerBeforeTunStream() {
        val events = mutableListOf<String>()
        val output = object : OutputStream() {
            override fun write(value: Int) = Unit
            override fun close() { events.add("stream closed") }
        }
        runVpnTunnelReader(
            openInput = { ByteArrayInputStream(byteArrayOf(7)) },
            openOutput = { output },
            isActive = { true },
            onOutputOpened = { events.add("native started") },
            handlePacket = { _, _, _ -> events.add("packet handled") },
            onOutputClosing = { events.add("native closed") },
            onEnded = { events.add("ended") }
        )
        assertEquals(
            listOf("native started", "packet handled", "native closed", "stream closed", "ended"),
            events
        )
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
    fun stoppingBlockedReaderClosesOwnedInputBeforeJoiningAndSuppressesFailure() {
        val active = AtomicBoolean(true)
        val input = BlockingInputStream()
        val owner = VpnTunnelInputOwner()
        val output = TrackingOutputStream()
        val ended = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val failures = mutableListOf<String?>()
        var readerException: Throwable? = null
        val reader = Thread {
            try {
                runVpnTunnelReader(
                    openInput = { owner.open { input } },
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

        active.set(false)
        owner.stop()
        reader.join(1_000)
        assertFalse(reader.isAlive, "Reader remained blocked after input close")

        assertTrue(finished.await(0, TimeUnit.SECONDS))
        assertTrue(ended.await(0, TimeUnit.SECONDS))
        assertNull(readerException)
        assertEquals(listOf(null), synchronized(failures) { failures.toList() })
        assertTrue(input.closed)
        assertTrue(output.closed)
    }

    @Test
    fun stopClosesAnInputThatFinishesOpeningAfterStop() {
        val owner = VpnTunnelInputOwner()
        val opening = CountDownLatch(1)
        val finishOpen = CountDownLatch(1)
        val input = TrackingInputStream(ByteArrayInputStream(byteArrayOf(1)))
        var failure: Throwable? = null
        val opener = Thread {
            try {
                owner.open {
                    opening.countDown()
                    assertTrue(finishOpen.await(1, TimeUnit.SECONDS))
                    input
                }
            } catch (error: Throwable) { failure = error }
        }.apply { isDaemon = true; start() }
        try {
            assertTrue(opening.await(1, TimeUnit.SECONDS))
            owner.stop()
        } finally {
            finishOpen.countDown()
            opener.join(1_000)
        }
        assertFalse(opener.isAlive)
        assertTrue(input.closed)
        assertTrue(failure is IOException, "Late input must be rejected before a read")
        owner.stop()
    }

    @Test
    fun stopBeforeOpenDoesNotAllocateAReader() {
        val owner = VpnTunnelInputOwner()
        owner.stop()
        var opened = false
        val failure = runCatching {
            owner.open { opened = true; ByteArrayInputStream(byteArrayOf(1)) }
        }.exceptionOrNull()
        assertTrue(failure is IOException)
        assertFalse(opened)
        owner.stop()
    }

    @Test
    fun stopWakesAReadThroughTheOwnedInterruptibleChannel() {
        val owner = VpnTunnelInputOwner()
        val pipe = java.nio.channels.Pipe.open()
        val entered = CountDownLatch(1)
        var failure: Throwable? = null
        val input = owner.open { java.nio.channels.Channels.newInputStream(pipe.source()) }
        val reader = Thread {
            try {
                entered.countDown()
                input.read(ByteArray(4096))
            } catch (error: Throwable) { failure = error }
        }.apply { isDaemon = true; start() }
        try {
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            assertTrue(reader.isAlive)
            owner.stop()
            reader.join(1_000)
            assertFalse(reader.isAlive, "STOP must wake read before joining")
            assertTrue(failure is IOException)
            assertFalse(pipe.source().isOpen)
            owner.stop()
        } finally {
            owner.stop()
            pipe.sink().close()
            reader.join(1_000)
        }
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
