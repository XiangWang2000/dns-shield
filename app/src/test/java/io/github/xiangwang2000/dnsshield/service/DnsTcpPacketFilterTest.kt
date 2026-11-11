package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DnsTcpPacketFilterTest {
    @Test
    fun recognizesOnlyVirtualDnsTcpForBothIpVersions() {
        assertTrue(isDnsTcpPacket(ipv4Packet(), 40))
        assertFalse(isDnsTcpPacket(ipv4Packet(destination = byteArrayOf(10, 0, 0, 3)), 40))
        assertFalse(isDnsTcpPacket(ipv4Packet(destinationPort = 54), 40))
        assertFalse(isDnsTcpPacket(ipv4Packet().also { it[9] = 17 }, 40))
        assertFalse(isDnsTcpPacket(ipv4Packet().also { it[32] = 0x40 }, 40))
        assertTrue(isDnsTcpPacket(ipv6Packet(), 60))
        assertFalse(isDnsTcpPacket(ipv6Packet(destination = IPV6_OTHER), 60))
        assertFalse(isDnsTcpPacket(ipv6Packet(destinationPort = 54), 60))
        assertFalse(isDnsTcpPacket(ipv6Packet().also { it[6] = 17 }, 60))
    }

    @Test
    fun acceptsBoundedIpv6ExtensionHeadersAndAtomicFragment() {
        assertTrue(isDnsTcpPacket(ipv6Packet(extensionHeaders = listOf(IPV6_DESTINATION_OPTIONS)), 68))
        assertTrue(isDnsTcpPacket(ipv6Packet(extensionHeaders = listOf(IPV6_FRAGMENT)), 68))
        assertFalse(isDnsTcpPacket(ipv6Packet(extensionHeaders = listOf(IPV6_FRAGMENT), fragmentField = 1), 68))
        assertFalse(isDnsTcpPacket(ipv6Packet(extensionHeaders = listOf(IPV6_ROUTING)), 68))
        assertFalse(isDnsTcpPacket(ipv6Packet(extensionHeaders = List(9) { IPV6_DESTINATION_OPTIONS }), 132))
    }

    @Test
    fun rejectsTruncatedOrLengthInconsistentPacketsUsingReadLength() {
        val ipv4Packet = ipv4Packet().copyOf(50)
        assertTrue(isDnsTcpPacket(ipv4Packet, 40))
        assertFalse(isDnsTcpPacket(ipv4Packet, 41))
        val packet = ipv6Packet().copyOf(80)
        assertTrue(isDnsTcpPacket(packet, 60))
        assertFalse(isDnsTcpPacket(packet, 61))
        assertFalse(isDnsTcpPacket(packet, 59))
        assertFalse(isDnsTcpPacket(ipv6Packet(extensionHeaders = listOf(IPV6_DESTINATION_OPTIONS), extensionLength = 255), 68))
    }

    private fun ipv4Packet(
        destination: ByteArray = IPV4_DNS,
        destinationPort: Int = 53
    ): ByteArray = ByteArray(40).also { packet ->
        packet[0] = 0x45
        putU16(packet, 2, packet.size)
        packet[9] = 6
        byteArrayOf(10, 0, 0, 2).copyInto(packet, 12)
        destination.copyInto(packet, 16)
        putU16(packet, 20, 53000)
        putU16(packet, 22, destinationPort)
        packet[32] = 0x50
    }

    private fun ipv6Packet(
        destination: ByteArray = IPV6_DNS,
        destinationPort: Int = 53,
        extensionHeaders: List<Int> = emptyList(),
        fragmentField: Int = 0,
        extensionLength: Int = 0
    ): ByteArray {
        val length = 40 + extensionHeaders.size * 8 + 20
        return ByteArray(length).also { packet ->
            packet[0] = 0x60
            putU16(packet, 4, length - 40)
            packet[6] = (extensionHeaders.firstOrNull() ?: 6).toByte()
            IPV6_CLIENT.copyInto(packet, 8)
            destination.copyInto(packet, 24)
            var offset = 40
            extensionHeaders.forEachIndexed { index, type ->
                packet[offset] = (extensionHeaders.getOrNull(index + 1) ?: 6).toByte()
                if (type == IPV6_FRAGMENT) putU16(packet, offset + 2, fragmentField)
                else packet[offset + 1] = (if (extensionLength != 0) extensionLength else 0).toByte()
                offset += 8
            }
            putU16(packet, offset, 53000)
            putU16(packet, offset + 2, destinationPort)
            packet[offset + 12] = 0x50
        }
    }

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private companion object {
        val IPV4_DNS = byteArrayOf(10, 0, 0, 1)
        val IPV6_DNS = byteArrayOf(0xfd.toByte(), 0x29, 0x1a, 0x5d, 0x7c, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
        val IPV6_OTHER = IPV6_DNS.copyOf().also { it[15] = 3 }
        val IPV6_CLIENT = IPV6_DNS.copyOf().also { it[15] = 2 }
        const val IPV6_DESTINATION_OPTIONS = 60
        const val IPV6_FRAGMENT = 44
        const val IPV6_ROUTING = 43
    }
}
