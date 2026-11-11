package io.github.xiangwang2000.dnsshield.service

internal sealed interface Ipv6UdpDnsParseResult {
    data class Query(val packet: ParsedIpv6UdpDnsQuery) : Ipv6UdpDnsParseResult
    data object NotDns : Ipv6UdpDnsParseResult
    data class Rejected(
        val reason: Ipv6PacketRejectionReason,
        val dnsErrorResponse: ParsedIpv6UdpDnsErrorResponse? = null
    ) : Ipv6UdpDnsParseResult
}

internal data class ParsedIpv6UdpDnsQuery(
    val sourceIp: ByteArray,
    val destinationIp: ByteArray,
    val sourcePort: Int,
    override val payload: ByteArray,
    override val query: ParsedDnsQuery
) : DnsClientQuery

internal data class ParsedIpv6UdpDnsErrorResponse(
    val clientIp: ByteArray,
    val resolverIp: ByteArray,
    val clientPort: Int,
    val dnsPayload: ByteArray
)

internal object DnsIpv6UdpQueryParser {
    private const val UDP_HEADER_BYTES = 8
    private const val UDP_PROTOCOL = 17
    private const val DNS_PORT = 53

    fun parse(packet: ByteArray, readLength: Int): Ipv6UdpDnsParseResult {
        val transport = when (val result = Ipv6TransportHeaderParser.parse(packet, readLength)) {
            is Ipv6TransportHeaderParseResult.Transport -> result
            Ipv6TransportHeaderParseResult.NotTransport -> return Ipv6UdpDnsParseResult.NotDns
            is Ipv6TransportHeaderParseResult.Rejected -> {
                return Ipv6UdpDnsParseResult.Rejected(result.reason)
            }
        }
        if (transport.protocol != UDP_PROTOCOL) return Ipv6UdpDnsParseResult.NotDns
        val udpOffset = transport.offset
        if (transport.totalLength - udpOffset < UDP_HEADER_BYTES) {
            return Ipv6UdpDnsParseResult.Rejected(Ipv6PacketRejectionReason.SHORT_UDP_HEADER)
        }

        val sourcePort = readUnsignedShort(packet, udpOffset)
        val destinationPort = readUnsignedShort(packet, udpOffset + 2)
        if (destinationPort != DNS_PORT) return Ipv6UdpDnsParseResult.NotDns
        if (sourcePort == 0) {
            return Ipv6UdpDnsParseResult.Rejected(Ipv6PacketRejectionReason.INVALID_SOURCE_PORT)
        }

        val udpLength = readUnsignedShort(packet, udpOffset + 4)
        if (udpLength == 0) {
            return Ipv6UdpDnsParseResult.Rejected(Ipv6PacketRejectionReason.UNSUPPORTED_JUMBOGRAM)
        }
        if (udpLength < UDP_HEADER_BYTES || udpLength != transport.totalLength - udpOffset) {
            return Ipv6UdpDnsParseResult.Rejected(Ipv6PacketRejectionReason.INVALID_UDP_LENGTH)
        }
        if (readUnsignedShort(packet, udpOffset + 6) == 0 || !hasValidUdpChecksum(packet, udpOffset, udpLength)) {
            return Ipv6UdpDnsParseResult.Rejected(Ipv6PacketRejectionReason.INVALID_UDP_CHECKSUM)
        }

        val payloadOffset = udpOffset + UDP_HEADER_BYTES
        val payload = packet.copyOfRange(payloadOffset, udpOffset + udpLength)
        val query = when (val parseResult = DnsMessageValidator.parseQuery(payload)) {
            is DnsQueryParseResult.Valid -> parseResult.query
            is DnsQueryParseResult.Rejected -> {
                val dnsErrorResponse = DnsMessageValidator.buildParseErrorResponse(payload, parseResult.reason)?.let {
                    ParsedIpv6UdpDnsErrorResponse(
                        clientIp = packet.copyOfRange(8, 24),
                        resolverIp = packet.copyOfRange(24, 40),
                        clientPort = sourcePort,
                        dnsPayload = it
                    )
                }
                return Ipv6UdpDnsParseResult.Rejected(
                    reason = Ipv6PacketRejectionReason.INVALID_DNS_MESSAGE,
                    dnsErrorResponse = dnsErrorResponse
                )
            }
        }

        return Ipv6UdpDnsParseResult.Query(
            ParsedIpv6UdpDnsQuery(
                sourceIp = packet.copyOfRange(8, 24),
                destinationIp = packet.copyOfRange(24, 40),
                sourcePort = sourcePort,
                payload = payload,
                query = query
            )
        )
    }

    private fun hasValidUdpChecksum(packet: ByteArray, udpOffset: Int, udpLength: Int): Boolean {
        var sum = 0L
        sum = addWords(packet, 8, 32, sum)
        sum += udpLength
        sum += UDP_PROTOCOL
        sum = addWords(packet, udpOffset, udpLength, sum)
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum == 0xFFFFL
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
