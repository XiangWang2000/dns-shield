package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class DnsIpv4UdpQueryParserTest {
    @Test
    fun parsesIpv4UdpDnsWithinTheActualReadLength() {
        val dnsQuery = DnsTestMessages.query()
        val packet = DnsTestMessages.ipv4UdpDnsPacket(dnsQuery)
        val parsed = assertIs<Ipv4UdpDnsParseResult.Query>(DnsIpv4UdpQueryParser.parse(packet, packet.size)).packet

        assertContentEquals(byteArrayOf(10, 0, 0, 2), parsed.sourceIp)
        assertContentEquals(byteArrayOf(10, 0, 0, 1), parsed.destinationIp)
        assertEquals(53000, parsed.sourcePort)
        assertContentEquals(dnsQuery, parsed.payload)

        assertEquals(
            PacketRejectionReason.INVALID_TOTAL_LENGTH,
            assertIs<Ipv4UdpDnsParseResult.Rejected>(DnsIpv4UdpQueryParser.parse(packet, packet.size - 1)).reason
        )
        assertEquals(
            PacketRejectionReason.INVALID_READ_LENGTH,
            assertIs<Ipv4UdpDnsParseResult.Rejected>(DnsIpv4UdpQueryParser.parse(packet, packet.size + 1)).reason
        )
    }

    @Test
    fun rejectsInvalidLengthsFragmentsAndMalformedDnsBeforeForwarding() {
        val valid = DnsTestMessages.ipv4UdpDnsPacket(DnsTestMessages.query())

        val badTotalLength = valid.copyOf().also { it[3] = (it[3].toInt() - 1).toByte() }
        val invalidHeaderLength = valid.copyOf().also { it[0] = 0x44 }
        val moreFragments = valid.copyOf().also { it[6] = 0x20 }
        val nonzeroFragmentOffset = valid.copyOf().also { it[7] = 1 }
        val shortUdpLength = valid.copyOf().also { it[25] = 7 }
        val shortDnsHeader = DnsTestMessages.ipv4UdpDnsPacket(ByteArray(11))

        assertRejectedWithoutFormErr(badTotalLength, PacketRejectionReason.INVALID_TOTAL_LENGTH)
        assertRejectedWithoutFormErr(invalidHeaderLength, PacketRejectionReason.INVALID_HEADER_LENGTH)
        assertRejectedWithoutFormErr(moreFragments, PacketRejectionReason.FRAGMENTED)
        assertRejectedWithoutFormErr(nonzeroFragmentOffset, PacketRejectionReason.FRAGMENTED)
        assertRejectedWithoutFormErr(shortUdpLength, PacketRejectionReason.INVALID_UDP_LENGTH)
        assertRejectedWithoutFormErr(shortDnsHeader, PacketRejectionReason.INVALID_DNS_MESSAGE)

        val nonQueryDns = DnsTestMessages.query().also { it[2] = (it[2].toInt() or 0x80).toByte() }
        assertRejectedWithoutFormErr(
            DnsTestMessages.ipv4UdpDnsPacket(nonQueryDns),
            PacketRejectionReason.INVALID_DNS_MESSAGE
        )
        val oversizedDns = ByteArray(DnsMessageValidator.MAX_DNS_MESSAGE_BYTES + 1)
        assertRejectedWithoutFormErr(
            DnsTestMessages.ipv4UdpDnsPacket(oversizedDns),
            PacketRejectionReason.INVALID_DNS_MESSAGE
        )
    }

    @Test
    fun synthesizesDnsErrorsForSafelyClassifiableRejectionsAndReturnsThemToClient() {
        val unsupportedOpcode = DnsTestMessages.query(transactionId = 0xCAFE).also { it[2] = 0x09 }
        val wrongQuestionCount = DnsTestMessages.query(transactionId = 0x1234).also { it[5] = 2 }
        val malformedQuestion = DnsTestMessages.query(transactionId = 0x4567).also { it[12] = 63 }

        listOf(
            unsupportedOpcode to 4,
            wrongQuestionCount to 1,
            malformedQuestion to 1
        ).forEach { (dnsQuery, expectedRcode) ->
            val result = rejected(DnsTestMessages.ipv4UdpDnsPacket(dnsQuery))
            assertEquals(PacketRejectionReason.INVALID_DNS_MESSAGE, result.reason)
            val dnsError = assertIs<ParsedIpv4UdpDnsErrorResponse>(result.dnsErrorResponse)
            assertContentEquals(byteArrayOf(10, 0, 0, 2), dnsError.clientIp)
            assertContentEquals(byteArrayOf(10, 0, 0, 1), dnsError.resolverIp)
            assertEquals(53000, dnsError.clientPort)
            assertEquals(12, dnsError.dnsPayload.size)
            assertEquals(readUnsignedShort(dnsQuery, 0), readUnsignedShort(dnsError.dnsPayload, 0))

            val requestFlags = readUnsignedShort(dnsQuery, 2)
            val responseFlags = readUnsignedShort(dnsError.dnsPayload, 2)
            assertEquals(
                0x8000 or (requestFlags and 0x7800) or (requestFlags and 0x0100) or expectedRcode,
                responseFlags
            )
            assertEquals(expectedRcode, responseFlags and 0x000F)
            assertEquals(0, readUnsignedShort(dnsError.dnsPayload, 4))
            assertEquals(0, readUnsignedShort(dnsError.dnsPayload, 6))
            assertEquals(0, readUnsignedShort(dnsError.dnsPayload, 8))
            assertEquals(0, readUnsignedShort(dnsError.dnsPayload, 10))

            val responsePacket = DnsResponsePacketBuilder.build(
                srcIp = dnsError.resolverIp,
                dstIp = dnsError.clientIp,
                srcPort = 53,
                dstPort = dnsError.clientPort,
                payload = dnsError.dnsPayload
            )
            assertContentEquals(byteArrayOf(10, 0, 0, 1), responsePacket.copyOfRange(12, 16))
            assertContentEquals(byteArrayOf(10, 0, 0, 2), responsePacket.copyOfRange(16, 20))
            assertEquals(53, readUnsignedShort(responsePacket, 20))
            assertEquals(53000, readUnsignedShort(responsePacket, 22))
            assertContentEquals(dnsError.dnsPayload, responsePacket.copyOfRange(28, responsePacket.size))
        }
    }

    private fun assertRejectedWithoutFormErr(packet: ByteArray, expectedReason: PacketRejectionReason) {
        val result = rejected(packet)
        assertEquals(expectedReason, result.reason)
        assertNull(result.dnsErrorResponse)
    }

    private fun rejected(packet: ByteArray): Ipv4UdpDnsParseResult.Rejected =
        assertIs<Ipv4UdpDnsParseResult.Rejected>(DnsIpv4UdpQueryParser.parse(packet, packet.size))
}
