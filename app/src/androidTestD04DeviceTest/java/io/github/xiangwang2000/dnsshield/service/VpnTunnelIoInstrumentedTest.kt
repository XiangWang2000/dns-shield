package io.github.xiangwang2000.dnsshield.service

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class VpnTunnelIoInstrumentedTest {
    @Test
    fun actualParcelFileDescriptorSocketEofReportsUnexpectedEnd() {
        val endpoints = ParcelFileDescriptor.createSocketPair()
        val readerEndpoint = endpoints[0]
        val peerEndpoint = endpoints[1]
        val input = FileInputStream(readerEndpoint.fileDescriptor)
        val output = FileOutputStream(readerEndpoint.fileDescriptor)
        val failures = mutableListOf<String?>()

        try {
            peerEndpoint.close()

            runVpnTunnelReader(
                openInput = { input },
                openOutput = { output },
                isActive = { true },
                handlePacket = { _, _, _ -> error("EOF must not produce a packet") },
                onEnded = { failures.add(it) }
            )

            assertEquals(listOf("Tunnel stream reached EOF unexpectedly"), failures)
        } finally {
            closeQuietly(readerEndpoint)
            closeQuietly(peerEndpoint)
        }
    }

    @Test
    fun closingActualParcelFileDescriptorBeforeReadReportsReadFailure() {
        val endpoints = ParcelFileDescriptor.createSocketPair()
        val readerEndpoint = endpoints[0]
        val peerEndpoint = endpoints[1]
        val input = FileInputStream(readerEndpoint.fileDescriptor)
        val output = FileOutputStream(readerEndpoint.fileDescriptor)
        val failures = mutableListOf<String?>()

        try {
            readerEndpoint.close()

            runVpnTunnelReader(
                openInput = { input },
                openOutput = { output },
                isActive = { true },
                handlePacket = { _, _, _ -> error("A failed read must not produce a packet") },
                onEnded = { failures.add(it) }
            )

            assertEquals(1, failures.size)
            assertTrue("Expected an actual descriptor read error, got ${failures.single()}",
                failures.single()?.startsWith("Tunnel read error:") == true)
        } finally {
            closeQuietly(readerEndpoint)
            closeQuietly(peerEndpoint)
        }
    }

    @Test
    fun closingActualParcelFileDescriptorUnblocksAndJoinsBlockedReader() = runBlocking {
        val endpoints = ParcelFileDescriptor.createSocketPair()
        val readerEndpoint = endpoints[0]
        val peerEndpoint = endpoints[1]
        val active = AtomicBoolean(true)
        val readStarted = CountDownLatch(1)
        val ended = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val failures = Collections.synchronizedList(mutableListOf<String?>())
        val readerException = AtomicReference<Throwable?>()
        val joinedAfterDescriptorClose = AtomicBoolean(false)
        val input = SignalingInputStream(FileInputStream(readerEndpoint.fileDescriptor), readStarted)
        val output = FileOutputStream(readerEndpoint.fileDescriptor)
        val reader = Thread {
            try {
                runVpnTunnelReader(
                    openInput = { input },
                    openOutput = { output },
                    isActive = active::get,
                    handlePacket = { _, _, _ -> error("A blocked read must not produce a packet") },
                    onEnded = {
                        failures.add(it)
                        ended.countDown()
                    }
                )
            } catch (exception: Throwable) {
                readerException.set(exception)
            } finally {
                finished.countDown()
            }
        }.apply {
            name = "vpn-pfd-reader-instrumented-test"
            isDaemon = true
        }

        try {
            reader.start()
            assertTrue("Reader did not enter its blocking PFD read",
                readStarted.await(2, TimeUnit.SECONDS))

            closeVpnTunnelThenJoin(
                closeDescriptor = {
                    active.set(false)
                    readerEndpoint.close()
                },
                joinSession = {
                    reader.join(2_000)
                    joinedAfterDescriptorClose.set(!reader.isAlive)
                },
                onCloseFailure = { throw it },
                onJoinFailure = { throw it }
            )

            if (reader.isAlive) {
                // Release the peer only for bounded test cleanup; it does not count as a pass.
                closeQuietly(peerEndpoint)
                reader.join(2_000)
            }

            assertTrue("Closing the local PFD did not unblock the real socket read",
                joinedAfterDescriptorClose.get())
            assertTrue("Reader did not finish after PFD close", finished.await(0, TimeUnit.SECONDS))
            assertTrue("Reader did not report its end", ended.await(0, TimeUnit.SECONDS))
            assertNull(readerException.get())
            assertEquals(listOf<String?>(null), synchronized(failures) { failures.toList() })
        } finally {
            active.set(false)
            closeQuietly(readerEndpoint)
            closeQuietly(peerEndpoint)
            if (reader.isAlive) {
                reader.join(2_000)
            }
        }
    }

    private fun closeQuietly(descriptor: ParcelFileDescriptor) {
        try {
            descriptor.close()
        } catch (_: IOException) {
        }
    }

    private class SignalingInputStream(
        private val delegate: InputStream,
        private val readStarted: CountDownLatch
    ) : InputStream() {
        override fun read(): Int {
            readStarted.countDown()
            return delegate.read()
        }

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            readStarted.countDown()
            return delegate.read(buffer, offset, length)
        }

        override fun close() = delegate.close()
    }
}
