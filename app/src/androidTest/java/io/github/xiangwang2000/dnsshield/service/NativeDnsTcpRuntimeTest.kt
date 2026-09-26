package io.github.xiangwang2000.dnsshield.service

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.ByteArrayOutputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeDnsTcpRuntimeTest {
    @Test fun reorderedRetransmittedSegmentsAndRepeatedShutdown() {
        repeat(2) {
            val packets = ArrayBlockingQueue<ByteArray>(128)
            val failed = AtomicBoolean(false)
            NativeDnsTcpRuntime(
                handler = { request, send -> send(request.reversedArray()) },
                sendPacket = { assertTrue(packets.offer(it)) },
                onFailure = { failed.set(true) }
            ).use { runtime ->
                runtime.start()
                assertFalse(runtime.offer(ByteArray(40), 40))
                var clientSeq = 1000L
                val syn = packet(clientSeq, 0, 2)
                assertTrue(runtime.offer(syn, syn.size))
                val synAck = awaitPacket(packets) { (it[33].toInt() and 0x12) == 0x12 }
                var serverSeq = u32(synAck, 24) + 1
                clientSeq++
                send(runtime, packet(clientSeq, serverSeq, 16))
                val frame = byteArrayOf(0, 5, 10, 20, 30, 40, 50)
                // The final segment arrives first, then the gap, then a duplicate.
                send(runtime, packet(clientSeq + 3, serverSeq, 24, frame.copyOfRange(3, frame.size)))
                send(runtime, packet(clientSeq, serverSeq, 24, frame.copyOfRange(0, 3)))
                send(runtime, packet(clientSeq, serverSeq, 24, frame.copyOfRange(0, 3)))
                clientSeq += frame.size
                val received = ByteArrayOutputStream()
                while (received.size() < frame.size) {
                    val response = awaitPacket(packets) { payload(it).isNotEmpty() }
                    assertEquals(serverSeq, u32(response, 24))
                    val bytes = payload(response)
                    received.write(bytes)
                    serverSeq += bytes.size
                    send(runtime, packet(clientSeq, serverSeq, 16))
                }
                assertArrayEquals(byteArrayOf(0, 5, 50, 40, 30, 20, 10), received.toByteArray())
                // A duplicate input must not produce a duplicate framed response.
                send(runtime, packet(clientSeq, serverSeq, 17))
                val fin = awaitPacket(packets) { it[33].toInt() and 1 != 0 }
                send(runtime, packet(clientSeq + 1, u32(fin, 24) + 1, 16))
                assertFalse(failed.get())
            }
            assertFalse(failed.get())
        }
    }

    @Test fun resetAndMalformedPacketDoNotKillStack() {
        val packets = ArrayBlockingQueue<ByteArray>(128)
        val failed = AtomicBoolean(false)
        NativeDnsTcpRuntime({ _, _ -> error("No DNS message should be delivered") },
            { packets.offer(it) }, { failed.set(true) }).use { runtime ->
            runtime.start()
            val wrongPort = packet(1000, 0, 2).also { it[23] = 54 }
            assertFalse(runtime.offer(wrongPort, wrongPort.size))
            val syn = packet(1000, 0, 2)
            send(runtime, syn)
            val reply = awaitPacket(packets) { it[33].toInt() and 2 != 0 }
            send(runtime, packet(1001, u32(reply, 24) + 1, 20))
            assertFalse(failed.get())
        }
    }

    private fun send(runtime: NativeDnsTcpRuntime, bytes: ByteArray) {
        assertTrue(runtime.offer(bytes, bytes.size))
    }
    private fun awaitPacket(queue: ArrayBlockingQueue<ByteArray>, predicate: (ByteArray) -> Boolean): ByteArray {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(8)
        while (System.nanoTime() < end) {
            val packet = queue.poll(100, TimeUnit.MILLISECONDS) ?: continue
            if (predicate(packet)) return packet
        }
        throw AssertionError("TCP packet timed out")
    }
    private fun payload(packet: ByteArray): ByteArray {
        val ip = (packet[0].toInt() and 15) * 4
        val tcp = (packet[ip + 12].toInt() ushr 4 and 15) * 4
        return packet.copyOfRange(ip + tcp, packet.size)
    }
    private fun u32(bytes: ByteArray, offset: Int): Long =
        (0..3).fold(0L) { value, index -> (value shl 8) or (bytes[offset + index].toLong() and 255) }
    private fun packet(seq: Long, ack: Long, flags: Int, data: ByteArray = byteArrayOf()): ByteArray {
        val bytes = ByteArray(40 + data.size)
        fun short(offset: Int, value: Int) { bytes[offset] = (value ushr 8).toByte(); bytes[offset + 1] = value.toByte() }
        fun long(offset: Int, value: Long) { repeat(4) { bytes[offset + it] = (value ushr (24 - it * 8)).toByte() } }
        bytes[0] = 0x45; short(2, bytes.size); bytes[8] = 64; bytes[9] = 6
        byteArrayOf(10, 0, 0, 2, 10, 0, 0, 1).copyInto(bytes, 12)
        short(20, 45678); short(22, 53); long(24, seq); long(28, ack)
        bytes[32] = 0x50; bytes[33] = flags.toByte(); short(34, 65535)
        data.copyInto(bytes, 40)
        short(10, checksum(bytes.copyOfRange(0, 20)))
        val pseudo = bytes.copyOfRange(12, 20) + byteArrayOf(0, 6, ((20 + data.size) ushr 8).toByte(), (20 + data.size).toByte())
        short(36, checksum(pseudo + bytes.copyOfRange(20, bytes.size)))
        return bytes
    }
    private fun checksum(bytes: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i < bytes.size) {
            sum += (bytes[i].toInt() and 255) * 256 + if (i + 1 < bytes.size) bytes[i + 1].toInt() and 255 else 0
            i += 2
        }
        while (sum ushr 16 != 0L) sum = (sum and 65535) + (sum ushr 16)
        return sum.toInt().inv() and 65535
    }
}
