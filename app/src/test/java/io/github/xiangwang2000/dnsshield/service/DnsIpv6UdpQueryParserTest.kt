package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class DnsIpv6UdpQueryParserTest {
    @Test
    fun parsesIpv6UdpDnsAndHonorsTheActualReadLength() {
        val query = DnsTestMessages.query()
        val packet = ipv6UdpPacket(query)
        val padded = packet.copyOf(packet.size + 12)
        val parsed = assertIs<Ipv6UdpDnsParseResult.Query>(DnsIpv6UdpQueryParser.parse(padded, packet.size)).packet

        assertContentEquals(SOURCE_IP, parsed.sourceIp)
        assertContentEquals(DESTINATION_IP, parsed.destinationIp)
        assertEquals(53000, parsed.sourcePort)
        assertContentEquals(query, parsed.payload)
        assertEquals(readUnsignedShort(query, 0), parsed.query.transactionId)

        assertEquals(
            Ipv6PacketRejectionReason.INVALID_PAYLOAD_LENGTH,
            rejected(DnsIpv6UdpQueryParser.parse(padded, padded.size)).reason
        )
        assertEquals(
            Ipv6PacketRejectionReason.INVALID_READ_LENGTH,
            rejected(DnsIpv6UdpQueryParser.parse(packet, packet.size + 1)).reason
        )
        assertEquals(
            Ipv6PacketRejectionReason.SHORT_IPV6_HEADER,
            rejected(DnsIpv6UdpQueryParser.parse(packet, 39)).reason
        )
    }

    @Test
    fun validatesUdpLengthAndMandatoryChecksumBeforeDnsParsing() {
        val valid = ipv6UdpPacket(DnsTestMessages.query())

        val badUdpLength = valid.copyOf().also {
            it[44] = 0
            it[45] = 7
        }
        val zeroChecksum = valid.copyOf().also {
            it[46] = 0
            it[47] = 0
        }
        val badChecksum = valid.copyOf().also { it[46] = (it[46].toInt() xor 1).toByte() }
        val zeroSourcePort = ipv6UdpPacket(DnsTestMessages.query(), sourcePort = 0)
        val malformedDns = ipv6UdpPacket(DnsTestMessages.query().also { it[12] = 63 })

        assertRejected(badUdpLength, Ipv6PacketRejectionReason.INVALID_UDP_LENGTH)
        assertRejected(zeroChecksum, Ipv6PacketRejectionReason.INVALID_UDP_CHECKSUM)
        assertRejected(badChecksum, Ipv6PacketRejectionReason.INVALID_UDP_CHECKSUM)
        assertRejected(zeroSourcePort, Ipv6PacketRejectionReason.INVALID_SOURCE_PORT)

        val dnsError = rejected(DnsIpv6UdpQueryParser.parse(malformedDns, malformedDns.size))
        assertEquals(Ipv6PacketRejectionReason.INVALID_DNS_MESSAGE, dnsError.reason)
        val response = assertIs<ParsedIpv6UdpDnsErrorResponse>(dnsError.dnsErrorResponse)
        assertContentEquals(SOURCE_IP, response.clientIp)
        assertContentEquals(DESTINATION_IP, response.resolverIp)
        assertEquals(53000, response.clientPort)
        assertEquals(12, response.dnsPayload.size)
    }

    @Test
    fun acceptsBoundedOptionsAndAtomicFragments() {
        val query = DnsTestMessages.query()
        val packet = ipv6UdpPacket(
            query,
            extensions = listOf(
                optionsHeader(0),
                fragmentHeader(),
                optionsHeader(60)
            )
        )
        val parsed = assertIs<Ipv6UdpDnsParseResult.Query>(DnsIpv6UdpQueryParser.parse(packet, packet.size)).packet
        assertContentEquals(query, parsed.payload)
        assertContentEquals(SOURCE_IP, parsed.sourceIp)
        assertContentEquals(DESTINATION_IP, parsed.destinationIp)
    }

    @Test
    fun rejectsRealFragmentsUnsafeRoutingAndSecurityHeaders() {
        val query = DnsTestMessages.query()
        val firstFragment = ipv6UdpPacket(query, extensions = listOf(fragmentHeader(field = 1)))
        val nonInitialFragment = ipv6UdpPacket(query, extensions = listOf(fragmentHeader(field = 8)))
        val invalidFragment = ipv6UdpPacket(query, extensions = listOf(fragmentHeader())).also { it[41] = 1 }
        val duplicateAtomicFragments = ipv6UdpPacket(
            query,
            extensions = listOf(fragmentHeader(), fragmentHeader())
        )
        val routing = ipv6UdpPacket(query, extensions = listOf(routingHeader()))
        val authentication = ipv6UdpPacket(query, extensions = listOf(authenticationHeader()))

        assertRejected(firstFragment, Ipv6PacketRejectionReason.FRAGMENTED)
        assertRejected(nonInitialFragment, Ipv6PacketRejectionReason.FRAGMENTED)
        assertRejected(invalidFragment, Ipv6PacketRejectionReason.INVALID_FRAGMENT_HEADER)
        assertRejected(duplicateAtomicFragments, Ipv6PacketRejectionReason.INVALID_FRAGMENT_HEADER)
        assertRejected(routing, Ipv6PacketRejectionReason.UNSUPPORTED_ROUTING_HEADER)
        assertRejected(authentication, Ipv6PacketRejectionReason.UNSUPPORTED_SECURITY_HEADER)

        val encrypted = ipv6UdpPacket(query, baseNextHeader = 50)
        assertRejected(encrypted, Ipv6PacketRejectionReason.UNSUPPORTED_SECURITY_HEADER)
    }

    @Test
    fun rejectsMalformedOrOverLimitExtensionHeadersAndOptions() {
        val query = DnsTestMessages.query()
        val shortHeader = ipv6UdpPacket(query, extensions = listOf(optionsHeader(0))).also { it[41] = 0xFF.toByte() }
        val misplacedHopByHop = ipv6UdpPacket(
            query,
            extensions = listOf(optionsHeader(60), optionsHeader(0))
        )
        val malformedOption = ipv6UdpPacket(
            query,
            extensions = listOf(optionsHeader(0, byteArrayOf(0x40, 0xFF.toByte(), 0, 0, 0, 0)))
        )
        val discardOption = ipv6UdpPacket(
            query,
            extensions = listOf(optionsHeader(60, byteArrayOf(0x40, 0, 0, 0, 0, 0)))
        )
        val tooManyExtensionBytes = ipv6UdpPacket(
            query,
            extensions = listOf(
                optionsHeader(0, ByteArray(86)),
                optionsHeader(60, ByteArray(86)),
                optionsHeader(60, ByteArray(86))
            )
        )
        val tooManyExtensionHeaders = ipv6UdpPacket(
            query,
            extensions = List(Ipv6TransportHeaderParser.MAX_EXTENSION_HEADERS + 1) { authenticationHeader() }
        )
        val jumbogram = ipv6UdpPacket(query, extensions = listOf(optionsHeader(0))).also {
            it[4] = 0
            it[5] = 0
        }

        assertRejected(shortHeader, Ipv6PacketRejectionReason.INVALID_EXTENSION_HEADER_LENGTH)
        assertRejected(misplacedHopByHop, Ipv6PacketRejectionReason.INVALID_EXTENSION_HEADER_ORDER)
        assertRejected(malformedOption, Ipv6PacketRejectionReason.INVALID_IPV6_OPTION_LENGTH)
        assertRejected(discardOption, Ipv6PacketRejectionReason.UNSUPPORTED_IPV6_OPTION)
        assertRejected(tooManyExtensionBytes, Ipv6PacketRejectionReason.EXTENSION_HEADER_LIMIT_EXCEEDED)
        assertRejected(tooManyExtensionHeaders, Ipv6PacketRejectionReason.EXTENSION_HEADER_LIMIT_EXCEEDED)
        assertRejected(jumbogram, Ipv6PacketRejectionReason.UNSUPPORTED_JUMBOGRAM)
    }

    @Test
    fun returnsNotDnsForOtherProtocolsAndNonDnsPorts() {
        val query = DnsTestMessages.query()
        val tcp = ipv6UdpPacket(query, baseNextHeader = 6)
        val mdns = ipv6UdpPacket(query, destinationPort = 5353)

        assertEquals(Ipv6UdpDnsParseResult.NotDns, DnsIpv6UdpQueryParser.parse(tcp, tcp.size))
        assertEquals(Ipv6UdpDnsParseResult.NotDns, DnsIpv6UdpQueryParser.parse(mdns, mdns.size))
    }

    private fun assertRejected(packet: ByteArray, expected: Ipv6PacketRejectionReason) {
        val result = rejected(DnsIpv6UdpQueryParser.parse(packet, packet.size))
        assertEquals(expected, result.reason)
        assertNull(result.dnsErrorResponse)
    }

    private fun rejected(result: Ipv6UdpDnsParseResult): Ipv6UdpDnsParseResult.Rejected =
        assertIs<Ipv6UdpDnsParseResult.Rejected>(result)

    private data class TestExtension(val protocol: Int, val bytes: ByteArray)

    private fun optionsHeader(protocol: Int, options: ByteArray = ByteArray(6)): TestExtension {
        val headerLength = ((options.size + 2 + 7) / 8) * 8
        return TestExtension(protocol, ByteArray(headerLength).also {
            it[1] = (headerLength / 8 - 1).toByte()
            System.arraycopy(options, 0, it, 2, options.size)
        })
    }

    private fun fragmentHeader(field: Int = 0): TestExtension = TestExtension(44, ByteArray(8).also {
        it[2] = (field ushr 8).toByte()
        it[3] = field.toByte()
    })

    private fun routingHeader(): TestExtension = TestExtension(43, ByteArray(8))

    private fun authenticationHeader(): TestExtension = TestExtension(51, ByteArray(12).also { it[1] = 1 })

    private fun ipv6UdpPacket(
        dnsPayload: ByteArray,
        extensions: List<TestExtension> = emptyList(),
        sourcePort: Int = 53000,
        destinationPort: Int = 53,
        baseNextHeader: Int? = null
    ): ByteArray {
        val extensionCopies = extensions.map { TestExtension(it.protocol, it.bytes.copyOf()) }
        extensionCopies.forEachIndexed { index, extension ->
            extension.bytes[0] = (extensionCopies.getOrNull(index + 1)?.protocol ?: 17).toByte()
        }
        val udpOffsetInPayload = extensionCopies.sumOf { it.bytes.size }
        val udpLength = 8 + dnsPayload.size
        val payloadLength = udpOffsetInPayload + udpLength
        val packet = ByteArray(40 + payloadLength)
        packet[0] = 0x60
        packet[4] = (payloadLength ushr 8).toByte()
        packet[5] = payloadLength.toByte()
        packet[6] = (baseNextHeader ?: extensionCopies.firstOrNull()?.protocol ?: 17).toByte()
        packet[7] = 64
        System.arraycopy(SOURCE_IP, 0, packet, 8, 16)
        System.arraycopy(DESTINATION_IP, 0, packet, 24, 16)

        var offset = 40
        extensionCopies.forEach {
            System.arraycopy(it.bytes, 0, packet, offset, it.bytes.size)
            offset += it.bytes.size
        }
        packet[offset] = (sourcePort ushr 8).toByte()
        packet[offset + 1] = sourcePort.toByte()
        packet[offset + 2] = (destinationPort ushr 8).toByte()
        packet[offset + 3] = destinationPort.toByte()
        packet[offset + 4] = (udpLength ushr 8).toByte()
        packet[offset + 5] = udpLength.toByte()
        System.arraycopy(dnsPayload, 0, packet, offset + 8, dnsPayload.size)
        val checksum = calculateChecksum(packet, offset, udpLength).let { if (it == 0) 0xFFFF else it }
        packet[offset + 6] = (checksum ushr 8).toByte()
        packet[offset + 7] = checksum.toByte()
        return packet
    }

    private fun calculateChecksum(packet: ByteArray, udpOffset: Int, udpLength: Int): Int {
        var sum = 0L
        sum = addWords(packet, 8, 32, sum)
        sum += udpLength
        sum += 17
        sum = addWords(packet, udpOffset, udpLength, sum)
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun addWords(packet: ByteArray, offset: Int, length: Int, initialSum: Long): Long {
        var sum = initialSum
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += ((packet[index].toInt() and 0xFF) shl 8) or (packet[index + 1].toInt() and 0xFF)
            index += 2
        }
        if (index < end) sum += (packet[index].toInt() and 0xFF) shl 8
        return sum
    }

    companion object {
        private val SOURCE_IP = byteArrayOf(
            0x20, 0x01, 0x0D, 0xB8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53
        )
        private val DESTINATION_IP = byteArrayOf(
            0x20, 0x01, 0x0D, 0xB8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
        )
    }
}
