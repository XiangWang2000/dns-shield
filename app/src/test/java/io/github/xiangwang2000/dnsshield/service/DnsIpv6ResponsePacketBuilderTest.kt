package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DnsIpv6ResponsePacketBuilderTest {
    @Test
    fun buildsKnownIpv6UdpChecksumVectorAndStampsTransactionId() {
        val packet = DnsIpv6ResponsePacketBuilder.build(
            sourceIp,
            destinationIp,
            srcPort = 53,
            dstPort = 53000,
            payload = byteArrayOf(0x12, 0x34)
        )

        assertEquals(0x60, packet[0].toInt() and 0xFF)
        assertEquals(10, readUnsignedShort(packet, 4))
        assertEquals(17, packet[6].toInt() and 0xFF)
        assertEquals(64, packet[7].toInt() and 0xFF)
        assertContentEquals(sourceIp, packet.copyOfRange(8, 24))
        assertContentEquals(destinationIp, packet.copyOfRange(24, 40))
        assertEquals(53, readUnsignedShort(packet, 40))
        assertEquals(53000, readUnsignedShort(packet, 42))
        assertEquals(10, readUnsignedShort(packet, 44))
        assertEquals(0xC2A1, readUnsignedShort(packet, 46))
        assertTrue(hasValidUdpChecksum(packet))

        val cached = ByteArray(64) { it.toByte() }
        val original = cached.copyOf()
        val response = DnsIpv6ResponsePacketBuilder.build(
            sourceIp,
            destinationIp,
            srcPort = 53,
            dstPort = 53000,
            payload = cached,
            transactionIdSource = byteArrayOf(0xAB.toByte(), 0xCD.toByte())
        )
        assertContentEquals(byteArrayOf(0xAB.toByte(), 0xCD.toByte()), response.copyOfRange(48, 50))
        assertContentEquals(original, cached)
        assertTrue(hasValidUdpChecksum(response))
    }

    @Test
    fun supportsEmptyAndMaximumNonJumboPayloadsAndExposesTunLimit() {
        val empty = DnsIpv6ResponsePacketBuilder.build(sourceIp, destinationIp, 53, 53000, ByteArray(0))
        assertEquals(8, readUnsignedShort(empty, 4))
        assertEquals(8, readUnsignedShort(empty, 44))
        assertTrue(hasValidUdpChecksum(empty))

        val largest = ByteArray(DnsIpv6ResponsePacketBuilder.MAX_UDP_PAYLOAD_BYTES) { 0x7F }
        val largePacket = DnsIpv6ResponsePacketBuilder.build(sourceIp, destinationIp, 53, 53000, largest)
        assertEquals(0xFFFF, readUnsignedShort(largePacket, 4))
        assertEquals(65_575, largePacket.size)
        assertTrue(hasValidUdpChecksum(largePacket))
        assertEquals(1_452, DnsIpv6ResponsePacketBuilder.MAX_TUN_UDP_PAYLOAD_BYTES)
        assertFailsWith<IllegalArgumentException> {
            DnsIpv6ResponsePacketBuilder.build(
                sourceIp,
                destinationIp,
                53,
                53000,
                ByteArray(DnsIpv6ResponsePacketBuilder.MAX_UDP_PAYLOAD_BYTES + 1)
            )
        }
    }

    @Test
    fun encodesAComputedZeroChecksumAsAllOnes() {
        val udp = ByteArray(10)
        udp[0] = 0
        udp[1] = 53
        udp[2] = (53000 ushr 8).toByte()
        udp[3] = 53000.toByte()
        udp[4] = 0
        udp[5] = 10
        var found = false
        for (value in 0..0xFFFF) {
            udp[8] = (value ushr 8).toByte()
            udp[9] = value.toByte()
            if (rawChecksum(sourceIp, destinationIp, udp) == 0) {
                found = true
                break
            }
        }
        assertTrue(found)

        val packet = DnsIpv6ResponsePacketBuilder.build(
            sourceIp,
            destinationIp,
            53,
            53000,
            udp.copyOfRange(8, 10)
        )
        assertEquals(0xFFFF, readUnsignedShort(packet, 46))
        assertTrue(hasValidUdpChecksum(packet))
    }

    private fun hasValidUdpChecksum(packet: ByteArray): Boolean {
        val udpLength = readUnsignedShort(packet, 44)
        val bytes = ByteArray(40 + udpLength)
        System.arraycopy(packet, 8, bytes, 0, 32)
        bytes[34] = (udpLength ushr 8).toByte()
        bytes[35] = udpLength.toByte()
        bytes[39] = 17
        System.arraycopy(packet, 40, bytes, 40, udpLength)
        return foldedSum(bytes) == 0xFFFF
    }

    private fun rawChecksum(source: ByteArray, destination: ByteArray, udp: ByteArray): Int {
        val bytes = ByteArray(40 + udp.size)
        System.arraycopy(source, 0, bytes, 0, 16)
        System.arraycopy(destination, 0, bytes, 16, 16)
        bytes[34] = (udp.size ushr 8).toByte()
        bytes[35] = udp.size.toByte()
        bytes[39] = 17
        System.arraycopy(udp, 0, bytes, 40, udp.size)
        return foldedSum(bytes).inv() and 0xFFFF
    }

    private fun foldedSum(bytes: ByteArray): Int {
        var sum = 0L
        var offset = 0
        while (offset + 1 < bytes.size) {
            sum += ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
            offset += 2
        }
        if (offset < bytes.size) sum += (bytes[offset].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.toInt() and 0xFFFF
    }

    companion object {
        private val sourceIp = byteArrayOf(
            0x20, 0x01, 0x0D, 0xB8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53
        )
        private val destinationIp = byteArrayOf(
            0x20, 0x01, 0x0D, 0xB8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
        )
    }
}
