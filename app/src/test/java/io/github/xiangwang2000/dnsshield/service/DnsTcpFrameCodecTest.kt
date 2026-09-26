package io.github.xiangwang2000.dnsshield.service

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.ReadableByteChannel
import java.nio.channels.WritableByteChannel
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsTcpFrameCodecTest {
    @org.junit.Test(timeout = 1000)
    fun rejectsZeroProgressReadWithoutClosingCallerChannel() {
        val input = PartialReadableChannel(ByteArrayInputStream(byteArrayOf(0, 1, 42)), maxChunk = 0)
        assertFailsWith<IOException> { DnsTcpFrameCodec.readFrame(input) }
        assertTrue(input.isOpen)
    }

    @org.junit.Test(timeout = 1000)
    fun rejectsZeroProgressWriteWithoutClosingCallerChannel() {
        val output = PartialWritableChannel(ByteArrayOutputStream(), maxChunk = 0)
        assertFailsWith<IOException> { DnsTcpFrameCodec.writeFrame(output, byteArrayOf(42)) }
        assertTrue(output.isOpen)
    }

    @Test
    fun writesAndReadsMultipleFramesAcrossPartialChannels() {
        val bytes = ByteArrayOutputStream()
        val output = PartialWritableChannel(bytes, maxChunk = 1)
        val first = byteArrayOf(1, 2, 3)
        val second = byteArrayOf(9, 8)

        DnsTcpFrameCodec.writeFrame(output, first)
        DnsTcpFrameCodec.writeFrame(output, second)

        val input = PartialReadableChannel(ByteArrayInputStream(bytes.toByteArray()), maxChunk = 1)
        assertContentEquals(first, DnsTcpFrameCodec.readFrame(input))
        assertContentEquals(second, DnsTcpFrameCodec.readFrame(input))
        assertNull(DnsTcpFrameCodec.readFrame(input))
    }

    @Test
    fun rejectsZeroAndOversizedFrames() {
        assertFailsWith<DnsTcpFrameException> {
            DnsTcpFrameCodec.readFrame(ByteArrayInputStream(byteArrayOf(0, 0)))
        }
        assertFailsWith<DnsTcpFrameException> {
            DnsTcpFrameCodec.readFrame(ByteArrayInputStream(byteArrayOf(0, 5, 1, 2, 3, 4, 5)), maxMessageBytes = 4)
        }
    }

    @Test
    fun rejectsTruncatedPrefixAndBody() {
        assertFailsWith<EOFException> {
            DnsTcpFrameCodec.readFrame(ByteArrayInputStream(byteArrayOf(0)))
        }
        assertFailsWith<EOFException> {
            DnsTcpFrameCodec.readFrame(ByteArrayInputStream(byteArrayOf(0, 3, 1, 2)))
        }
    }

    @Test
    fun rejectsInvalidOutboundFrames() {
        assertFailsWith<IllegalArgumentException> {
            DnsTcpFrameCodec.writeFrame(ByteArrayOutputStream(), byteArrayOf())
        }
        assertFailsWith<IllegalArgumentException> {
            DnsTcpFrameCodec.writeFrame(ByteArrayOutputStream(), byteArrayOf(1, 2), maxMessageBytes = 1)
        }
    }

    private class PartialReadableChannel(
        private val input: ByteArrayInputStream,
        private val maxChunk: Int
    ) : ReadableByteChannel {
        private var open = true

        override fun read(target: ByteBuffer): Int {
            if (!open) return -1
            if (input.available() == 0) return -1
            val count = minOf(target.remaining(), maxChunk, input.available())
            repeat(count) { target.put(input.read().toByte()) }
            return count
        }

        override fun isOpen(): Boolean = open

        override fun close() {
            open = false
        }
    }

    private class PartialWritableChannel(
        private val output: ByteArrayOutputStream,
        private val maxChunk: Int
    ) : WritableByteChannel {
        private var open = true

        override fun write(source: ByteBuffer): Int {
            if (!open) return -1
            val count = minOf(source.remaining(), maxChunk)
            repeat(count) { output.write(source.get().toInt()) }
            return count
        }

        override fun isOpen(): Boolean = open

        override fun close() {
            open = false
        }
    }
}
