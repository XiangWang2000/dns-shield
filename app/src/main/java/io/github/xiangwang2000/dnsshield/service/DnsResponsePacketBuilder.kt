package io.github.xiangwang2000.dnsshield.service

/** Builds the IPv4/UDP envelope and can stamp the client's DNS transaction ID during the copy. */
internal object DnsResponsePacketBuilder {
    fun build(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        transactionIdSource: ByteArray? = null
    ): ByteArray {
        val ipHeaderLength = 20
        val udpHeaderLength = 8
        val totalLength = ipHeaderLength + udpHeaderLength + payload.size
        val packet = ByteArray(totalLength)

        packet[0] = 0x45.toByte()
        packet[2] = ((totalLength shr 8) and 0xFF).toByte()
        packet[3] = (totalLength and 0xFF).toByte()
        packet[6] = 0x40.toByte()
        packet[8] = 64.toByte()
        packet[9] = 17.toByte()
        System.arraycopy(srcIp, 0, packet, 12, 4)
        System.arraycopy(dstIp, 0, packet, 16, 4)

        val ipChecksum = calculateChecksum(packet, 0, ipHeaderLength)
        packet[10] = ((ipChecksum shr 8) and 0xFF).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        val udpOffset = ipHeaderLength
        packet[udpOffset] = ((srcPort shr 8) and 0xFF).toByte()
        packet[udpOffset + 1] = (srcPort and 0xFF).toByte()
        packet[udpOffset + 2] = ((dstPort shr 8) and 0xFF).toByte()
        packet[udpOffset + 3] = (dstPort and 0xFF).toByte()
        val udpLength = udpHeaderLength + payload.size
        packet[udpOffset + 4] = ((udpLength shr 8) and 0xFF).toByte()
        packet[udpOffset + 5] = (udpLength and 0xFF).toByte()

        val payloadOffset = udpOffset + udpHeaderLength
        System.arraycopy(payload, 0, packet, payloadOffset, payload.size)
        if (payload.size >= 2 && transactionIdSource != null && transactionIdSource.size >= 2) {
            packet[payloadOffset] = transactionIdSource[0]
            packet[payloadOffset + 1] = transactionIdSource[1]
        }
        return packet
    }

    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var index = offset
        val end = offset + length
        while (index < end - 1) {
            sum += ((data[index].toInt() and 0xFF) shl 8) or
                (data[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (index < end) sum += (data[index].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv() and 0xFFFF
    }
}
