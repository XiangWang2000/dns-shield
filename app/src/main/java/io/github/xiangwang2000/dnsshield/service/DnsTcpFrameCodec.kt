package io.github.xiangwang2000.dnsshield.service

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.channels.ReadableByteChannel
import java.nio.channels.WritableByteChannel

/**
 * Reads and writes DNS-over-TCP frames through blocking streams/channels.
 * Zero-progress I/O is rejected; non-blocking readiness belongs to the caller.
 * The caller owns the connection and must close it to cancel blocking I/O.
 */
internal object DnsTcpFrameCodec {
    const val MAX_DNS_MESSAGE_BYTES = 0xFFFF

    fun readFrame(
        input: InputStream,
        maxMessageBytes: Int = MAX_DNS_MESSAGE_BYTES
    ): ByteArray? = readFrame(Channels.newChannel(input), maxMessageBytes)

    fun readFrame(
        channel: ReadableByteChannel,
        maxMessageBytes: Int = MAX_DNS_MESSAGE_BYTES
    ): ByteArray? {
        requireValidLimit(maxMessageBytes)
        val lengthPrefix = ByteBuffer.allocate(2)
        if (!readFully(channel, lengthPrefix, allowCleanEof = true)) return null
        lengthPrefix.flip()
        val messageLength = ((lengthPrefix.get().toInt() and 0xFF) shl 8) or
            (lengthPrefix.get().toInt() and 0xFF)
        if (messageLength == 0 || messageLength > maxMessageBytes) {
            throw DnsTcpFrameException("Invalid DNS/TCP frame length: $messageLength")
        }

        val message = ByteBuffer.allocate(messageLength)
        readFully(channel, message, allowCleanEof = false)
        return message.array()
    }

    fun writeFrame(
        output: OutputStream,
        message: ByteArray,
        maxMessageBytes: Int = MAX_DNS_MESSAGE_BYTES
    ) {
        writeFrame(Channels.newChannel(output), message, maxMessageBytes)
        output.flush()
    }

    fun writeFrame(
        channel: WritableByteChannel,
        message: ByteArray,
        maxMessageBytes: Int = MAX_DNS_MESSAGE_BYTES
    ) {
        requireValidLimit(maxMessageBytes)
        require(message.isNotEmpty()) { "DNS/TCP frame must not be empty" }
        require(message.size <= maxMessageBytes) {
            "DNS/TCP frame is ${message.size} bytes; maximum is $maxMessageBytes"
        }

        val frame = ByteBuffer.allocate(message.size + 2)
        frame.put((message.size ushr 8).toByte())
        frame.put(message.size.toByte())
        frame.put(message)
        frame.flip()
        while (frame.hasRemaining()) {
            val written = channel.write(frame)
            if (written < 0) throw EOFException("DNS/TCP channel closed while writing")
            if (written == 0) throw IOException("DNS/TCP blocking channel made no write progress")
        }
    }

    private fun readFully(
        channel: ReadableByteChannel,
        target: ByteBuffer,
        allowCleanEof: Boolean
    ): Boolean {
        var readAny = false
        while (target.hasRemaining()) {
            val read = channel.read(target)
            when {
                read < 0 -> {
                    if (allowCleanEof && !readAny) return false
                    throw EOFException("Unexpected EOF in DNS/TCP frame")
                }
                read > 0 -> readAny = true
                else -> throw IOException("DNS/TCP blocking channel made no read progress")
            }
        }
        return true
    }

    private fun requireValidLimit(maxMessageBytes: Int) {
        require(maxMessageBytes in 1..MAX_DNS_MESSAGE_BYTES) {
            "DNS/TCP frame limit must be between 1 and $MAX_DNS_MESSAGE_BYTES bytes"
        }
    }
}

internal class DnsTcpFrameException(message: String) : IOException(message)
