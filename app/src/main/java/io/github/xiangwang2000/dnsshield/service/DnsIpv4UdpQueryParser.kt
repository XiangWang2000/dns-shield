package io.github.xiangwang2000.dnsshield.service

internal sealed interface Ipv4UdpDnsParseResult {
    data class Query(val packet: ParsedIpv4UdpDnsQuery) : Ipv4UdpDnsParseResult
    data object NotDns : Ipv4UdpDnsParseResult
    data class Rejected(
        val reason: PacketRejectionReason,
        val dnsErrorResponse: ParsedIpv4UdpDnsErrorResponse? = null
    ) : Ipv4UdpDnsParseResult
}

internal enum class PacketRejectionReason {
    INVALID_READ_LENGTH,
    SHORT_IPV4_HEADER,
    INVALID_VERSION,
    INVALID_HEADER_LENGTH,
    INVALID_TOTAL_LENGTH,
    FRAGMENTED,
    NOT_UDP,
    SHORT_UDP_HEADER,
    INVALID_UDP_LENGTH,
    INVALID_SOURCE_PORT,
    INVALID_DNS_MESSAGE
}

internal data class ParsedIpv4UdpDnsQuery(
    val sourceIp: ByteArray,
    val destinationIp: ByteArray,
    val sourcePort: Int,
    val payload: ByteArray,
    val query: ParsedDnsQuery
)

internal data class ParsedIpv4UdpDnsErrorResponse(
    val clientIp: ByteArray,
    val resolverIp: ByteArray,
    val clientPort: Int,
    val dnsPayload: ByteArray
)

internal object DnsIpv4UdpQueryParser {
    private const val IPV4_MIN_HEADER_BYTES = 20
    private const val UDP_HEADER_BYTES = 8

    fun parse(packet: ByteArray, readLength: Int): Ipv4UdpDnsParseResult {
        if (readLength < 0 || readLength > packet.size) {
            return Ipv4UdpDnsParseResult.Rejected(PacketRejectionReason.INVALID_READ_LENGTH)
        }
        if (readLength < IPV4_MIN_HEADER_BYTES) {
            return Ipv4UdpDnsParseResult.Rejected(PacketRejectionReason.SHORT_IPV4_HEADER)
        }

        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return Ipv4UdpDnsParseResult.Rejected(PacketRejectionReason.INVALID_VERSION)

        val headerLength = (packet[0].toInt() and 0x0F) * 4
        if (headerLength < IPV4_MIN_HEADER_BYTES || headerLength > readLength) {
            return Ipv4UdpDnsParseResult.Rejected(PacketRejectionReason.INVALID_HEADER_LENGTH)
        }

        val totalLength = readUnsignedShort(packet, 2)
        if (totalLength != readLength || totalLength < headerLength + UDP_HEADER_BYTES) {
            return Ipv4UdpDnsParseResult.Rejected(PacketRejectionReason.INVALID_TOTAL_LENGTH)
        }

        val fragment = readUnsignedShort(packet, 6)
        if (fragment and 0xBFFF != 0) return Ipv4UdpDnsParseResult.Rejected(PacketRejectionReason.FRAGMENTED)

        if (packet[9].toInt() and 0xFF != 17) return Ipv4UdpDnsParseResult.NotDns
        val udpOffset = headerLength
        val sourcePort = readUnsignedShort(packet, udpOffset)
        val destinationPort = readUnsignedShort(packet, udpOffset + 2)
        if (destinationPort != 53) return Ipv4UdpDnsParseResult.NotDns
        if (sourcePort == 0) return Ipv4UdpDnsParseResult.Rejected(PacketRejectionReason.INVALID_SOURCE_PORT)

        val udpLength = readUnsignedShort(packet, udpOffset + 4)
        if (udpLength < UDP_HEADER_BYTES || udpLength != totalLength - headerLength) {
            return Ipv4UdpDnsParseResult.Rejected(PacketRejectionReason.INVALID_UDP_LENGTH)
        }

        val payloadOffset = udpOffset + UDP_HEADER_BYTES
        val payload = packet.copyOfRange(payloadOffset, totalLength)
        val query = when (val parseResult = DnsMessageValidator.parseQuery(payload)) {
            is DnsQueryParseResult.Valid -> parseResult.query
            is DnsQueryParseResult.Rejected -> {
                val dnsErrorResponse = DnsMessageValidator.buildParseErrorResponse(payload, parseResult.reason)?.let { response ->
                    ParsedIpv4UdpDnsErrorResponse(
                        clientIp = packet.copyOfRange(12, 16),
                        resolverIp = packet.copyOfRange(16, 20),
                        clientPort = sourcePort,
                        dnsPayload = response
                    )
                }
                return Ipv4UdpDnsParseResult.Rejected(
                    reason = PacketRejectionReason.INVALID_DNS_MESSAGE,
                    dnsErrorResponse = dnsErrorResponse
                )
            }
        }

        return Ipv4UdpDnsParseResult.Query(
            ParsedIpv4UdpDnsQuery(
                sourceIp = packet.copyOfRange(12, 16),
                destinationIp = packet.copyOfRange(16, 20),
                sourcePort = sourcePort,
                payload = payload,
                query = query
            )
        )
    }
}
