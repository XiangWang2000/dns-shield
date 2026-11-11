package io.github.xiangwang2000.dnsshield.service

/** Builds an IPv6/UDP envelope; callers provide the reversed packet addresses. */
internal object DnsIpv6ResponsePacketBuilder {
    const val TUN_MTU_BYTES = 1500
    const val IPV6_HEADER_BYTES = 40
    const val UDP_HEADER_BYTES = 8
    const val MAX_UDP_PAYLOAD_BYTES = 0xFFFF - UDP_HEADER_BYTES
    const val MAX_TUN_UDP_PAYLOAD_BYTES = TUN_MTU_BYTES - IPV6_HEADER_BYTES - UDP_HEADER_BYTES

    fun build(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        transactionIdSource: ByteArray? = null
    ): ByteArray {
        require(srcIp.size == 16) { "IPv6 source address must contain 16 bytes" }
        require(dstIp.size == 16) { "IPv6 destination address must contain 16 bytes" }
        require(srcPort in 0..0xFFFF && dstPort in 0..0xFFFF) { "UDP ports must fit in 16 bits" }
        require(payload.size <= MAX_UDP_PAYLOAD_BYTES) { "UDP payload exceeds the IPv6 non-jumbogram limit" }

        val udpLength = UDP_HEADER_BYTES + payload.size
        val packet = ByteArray(IPV6_HEADER_BYTES + udpLength)
        packet[0] = 0x60
        packet[4] = (udpLength ushr 8).toByte()
        packet[5] = udpLength.toByte()
        packet[6] = 17
        packet[7] = 64
        System.arraycopy(srcIp, 0, packet, 8, 16)
        System.arraycopy(dstIp, 0, packet, 24, 16)

        val udpOffset = IPV6_HEADER_BYTES
        writeUnsignedShort(packet, udpOffset, srcPort)
        writeUnsignedShort(packet, udpOffset + 2, dstPort)
        writeUnsignedShort(packet, udpOffset + 4, udpLength)
        val payloadOffset = udpOffset + UDP_HEADER_BYTES
        System.arraycopy(payload, 0, packet, payloadOffset, payload.size)
        if (payload.size >= 2 && transactionIdSource != null && transactionIdSource.size >= 2) {
            packet[payloadOffset] = transactionIdSource[0]
            packet[payloadOffset + 1] = transactionIdSource[1]
        }

        val checksum = calculateUdpChecksum(packet, udpOffset, udpLength).let { if (it == 0) 0xFFFF else it }
        writeUnsignedShort(packet, udpOffset + 6, checksum)
        return packet
    }

    private fun writeUnsignedShort(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = (value ushr 8).toByte()
        packet[offset + 1] = value.toByte()
    }

    private fun calculateUdpChecksum(packet: ByteArray, udpOffset: Int, udpLength: Int): Int {
        var sum = 0L
        sum = addWords(packet, 8, 32, sum)
        sum += udpLength
        sum += 17
        sum = addWords(packet, udpOffset, udpLength, sum)
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun addWords(data: ByteArray, offset: Int, length: Int, initialSum: Long): Long {
        var sum = initialSum
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += ((data[index].toInt() and 0xFF) shl 8) or (data[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (index < end) sum += (data[index].toInt() and 0xFF) shl 8
        return sum
    }
}
