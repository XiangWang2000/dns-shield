package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

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
        val malformedDns = DnsTestMessages.ipv4UdpDnsPacket(ByteArray(12))

        assertEquals(PacketRejectionReason.INVALID_TOTAL_LENGTH, rejected(badTotalLength))
        assertEquals(PacketRejectionReason.INVALID_HEADER_LENGTH, rejected(invalidHeaderLength))
        assertEquals(PacketRejectionReason.FRAGMENTED, rejected(moreFragments))
        assertEquals(PacketRejectionReason.FRAGMENTED, rejected(nonzeroFragmentOffset))
        assertEquals(PacketRejectionReason.INVALID_UDP_LENGTH, rejected(shortUdpLength))
        assertEquals(PacketRejectionReason.INVALID_DNS_MESSAGE, rejected(malformedDns))
    }

    private fun rejected(packet: ByteArray): PacketRejectionReason =
        assertIs<Ipv4UdpDnsParseResult.Rejected>(DnsIpv4UdpQueryParser.parse(packet, packet.size)).reason
}
