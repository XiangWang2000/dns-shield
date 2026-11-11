package io.github.xiangwang2000.dnsshield.service

internal enum class Ipv6PacketRejectionReason {
    INVALID_READ_LENGTH,
    SHORT_IPV6_HEADER,
    INVALID_VERSION,
    INVALID_PAYLOAD_LENGTH,
    UNSUPPORTED_JUMBOGRAM,
    SHORT_EXTENSION_HEADER,
    INVALID_EXTENSION_HEADER_LENGTH,
    EXTENSION_HEADER_LIMIT_EXCEEDED,
    INVALID_EXTENSION_HEADER_ORDER,
    INVALID_IPV6_OPTION_LENGTH,
    INVALID_IPV6_OPTION,
    UNSUPPORTED_IPV6_OPTION,
    INVALID_FRAGMENT_HEADER,
    FRAGMENTED,
    UNSUPPORTED_ROUTING_HEADER,
    UNSUPPORTED_SECURITY_HEADER,
    SHORT_UDP_HEADER,
    INVALID_UDP_LENGTH,
    INVALID_SOURCE_PORT,
    INVALID_UDP_CHECKSUM,
    INVALID_DNS_MESSAGE
}

internal sealed interface Ipv6TransportHeaderParseResult {
    data class Transport(val protocol: Int, val offset: Int, val totalLength: Int) : Ipv6TransportHeaderParseResult
    data object NotTransport : Ipv6TransportHeaderParseResult
    data class Rejected(val reason: Ipv6PacketRejectionReason) : Ipv6TransportHeaderParseResult
}

/**
 * Walks at most 8 extension headers / 256 bytes without copying packet data.
 * Only bounded options headers and atomic fragments are accepted; jumbograms,
 * routing/AH/ESP for TCP or UDP, and real fragments are rejected without reassembly.
 */
internal object Ipv6TransportHeaderParser {
    const val IPV6_HEADER_BYTES = 40
    const val MAX_EXTENSION_HEADERS = 8
    const val MAX_EXTENSION_BYTES = 256

    private const val TCP_PROTOCOL = 6
    private const val UDP_PROTOCOL = 17
    private const val HOP_BY_HOP_PROTOCOL = 0
    private const val ROUTING_PROTOCOL = 43
    private const val FRAGMENT_PROTOCOL = 44
    private const val AH_PROTOCOL = 51
    private const val DESTINATION_OPTIONS_PROTOCOL = 60
    private const val ESP_PROTOCOL = 50

    fun parse(packet: ByteArray, readLength: Int): Ipv6TransportHeaderParseResult {
        if (readLength < 0 || readLength > packet.size) {
            return Ipv6TransportHeaderParseResult.Rejected(Ipv6PacketRejectionReason.INVALID_READ_LENGTH)
        }
        if (readLength < IPV6_HEADER_BYTES) {
            return Ipv6TransportHeaderParseResult.Rejected(Ipv6PacketRejectionReason.SHORT_IPV6_HEADER)
        }
        if ((packet[0].toInt() ushr 4) and 0x0F != 6) {
            return Ipv6TransportHeaderParseResult.Rejected(Ipv6PacketRejectionReason.INVALID_VERSION)
        }

        val payloadLength = readUnsignedShort(packet, 4)
        if (payloadLength == 0 && readLength > IPV6_HEADER_BYTES) {
            val reason = if ((packet[6].toInt() and 0xFF) == HOP_BY_HOP_PROTOCOL) {
                Ipv6PacketRejectionReason.UNSUPPORTED_JUMBOGRAM
            } else {
                Ipv6PacketRejectionReason.INVALID_PAYLOAD_LENGTH
            }
            return Ipv6TransportHeaderParseResult.Rejected(reason)
        }
        val totalLength = IPV6_HEADER_BYTES + payloadLength
        if (totalLength != readLength) {
            return Ipv6TransportHeaderParseResult.Rejected(Ipv6PacketRejectionReason.INVALID_PAYLOAD_LENGTH)
        }

        var protocol = packet[6].toInt() and 0xFF
        var offset = IPV6_HEADER_BYTES
        var extensionHeaderCount = 0
        var extensionBytes = 0
        var destinationOptionsCount = 0
        var destinationOptionsAfterFragmentSeen = false
        var hopByHopSeen = false
        var fragmentSeen = false
        var routingHeaderSeen = false
        var securityHeaderSeen = false
        var deferredRejection: Ipv6PacketRejectionReason? = null

        while (true) {
            when (protocol) {
                TCP_PROTOCOL, UDP_PROTOCOL -> break
                HOP_BY_HOP_PROTOCOL,
                ROUTING_PROTOCOL,
                FRAGMENT_PROTOCOL,
                AH_PROTOCOL,
                DESTINATION_OPTIONS_PROTOCOL -> {
                    if (extensionHeaderCount >= MAX_EXTENSION_HEADERS) {
                        return Ipv6TransportHeaderParseResult.Rejected(
                            Ipv6PacketRejectionReason.EXTENSION_HEADER_LIMIT_EXCEEDED
                        )
                    }
                    extensionHeaderCount++

                    val extensionLength = when (protocol) {
                        FRAGMENT_PROTOCOL -> 8
                        AH_PROTOCOL -> {
                            if (offset + 2 > totalLength) {
                                return Ipv6TransportHeaderParseResult.Rejected(
                                    Ipv6PacketRejectionReason.SHORT_EXTENSION_HEADER
                                )
                            }
                            val length = ((packet[offset + 1].toInt() and 0xFF) + 2) * 4
                            if (length < 12) {
                                return Ipv6TransportHeaderParseResult.Rejected(
                                    Ipv6PacketRejectionReason.INVALID_EXTENSION_HEADER_LENGTH
                                )
                            }
                            length
                        }
                        else -> {
                            if (offset + 2 > totalLength) {
                                return Ipv6TransportHeaderParseResult.Rejected(
                                    Ipv6PacketRejectionReason.SHORT_EXTENSION_HEADER
                                )
                            }
                            ((packet[offset + 1].toInt() and 0xFF) + 1) * 8
                        }
                    }

                    if (offset + extensionLength > totalLength) {
                        return Ipv6TransportHeaderParseResult.Rejected(
                            Ipv6PacketRejectionReason.INVALID_EXTENSION_HEADER_LENGTH
                        )
                    }
                    extensionBytes += extensionLength
                    if (extensionBytes > MAX_EXTENSION_BYTES) {
                        return Ipv6TransportHeaderParseResult.Rejected(
                            Ipv6PacketRejectionReason.EXTENSION_HEADER_LIMIT_EXCEEDED
                        )
                    }

                    when (protocol) {
                        HOP_BY_HOP_PROTOCOL -> {
                            if (hopByHopSeen || offset != IPV6_HEADER_BYTES) {
                                return Ipv6TransportHeaderParseResult.Rejected(
                                    Ipv6PacketRejectionReason.INVALID_EXTENSION_HEADER_ORDER
                                )
                            }
                            hopByHopSeen = true
                            val optionRejection = validateOptions(packet, offset + 2, offset + extensionLength)
                            if (optionRejection == Ipv6PacketRejectionReason.UNSUPPORTED_IPV6_OPTION) {
                                deferredRejection = optionRejection
                            } else if (optionRejection != null) {
                                return Ipv6TransportHeaderParseResult.Rejected(optionRejection)
                            }
                        }

                        DESTINATION_OPTIONS_PROTOCOL -> {
                            destinationOptionsCount++
                            if (destinationOptionsCount > 2) {
                                return Ipv6TransportHeaderParseResult.Rejected(
                                    Ipv6PacketRejectionReason.INVALID_EXTENSION_HEADER_ORDER
                                )
                            }
                            if (!routingHeaderSeen) {
                                if (fragmentSeen) {
                                    if (destinationOptionsAfterFragmentSeen) {
                                        return Ipv6TransportHeaderParseResult.Rejected(
                                            Ipv6PacketRejectionReason.INVALID_EXTENSION_HEADER_ORDER
                                        )
                                    }
                                    destinationOptionsAfterFragmentSeen = true
                                } else if (destinationOptionsCount > 1) {
                                    return Ipv6TransportHeaderParseResult.Rejected(
                                        Ipv6PacketRejectionReason.INVALID_EXTENSION_HEADER_ORDER
                                    )
                                }
                            }
                            val optionRejection = validateOptions(packet, offset + 2, offset + extensionLength)
                            if (optionRejection == Ipv6PacketRejectionReason.UNSUPPORTED_IPV6_OPTION) {
                                deferredRejection = optionRejection
                            } else if (optionRejection != null) {
                                return Ipv6TransportHeaderParseResult.Rejected(optionRejection)
                            }
                        }

                        ROUTING_PROTOCOL -> {
                            if (routingHeaderSeen || fragmentSeen || securityHeaderSeen) {
                                return Ipv6TransportHeaderParseResult.Rejected(
                                    Ipv6PacketRejectionReason.INVALID_EXTENSION_HEADER_ORDER
                                )
                            }
                            routingHeaderSeen = true
                        }
                        AH_PROTOCOL -> securityHeaderSeen = true
                        FRAGMENT_PROTOCOL -> {
                            if (fragmentSeen) {
                                return Ipv6TransportHeaderParseResult.Rejected(
                                    Ipv6PacketRejectionReason.INVALID_FRAGMENT_HEADER
                                )
                            }
                            if (securityHeaderSeen || (destinationOptionsCount > 0 && !routingHeaderSeen)) {
                                return Ipv6TransportHeaderParseResult.Rejected(
                                    Ipv6PacketRejectionReason.INVALID_EXTENSION_HEADER_ORDER
                                )
                            }
                            fragmentSeen = true
                            val fragmentField = readUnsignedShort(packet, offset + 2)
                            if (packet[offset + 1].toInt() != 0 || fragmentField and 0x0006 != 0) {
                                return Ipv6TransportHeaderParseResult.Rejected(
                                    Ipv6PacketRejectionReason.INVALID_FRAGMENT_HEADER
                                )
                            }
                            if (fragmentField and 0xFFF8 != 0 || fragmentField and 0x0001 != 0) {
                                return Ipv6TransportHeaderParseResult.Rejected(Ipv6PacketRejectionReason.FRAGMENTED)
                            }
                        }
                    }

                    protocol = packet[offset].toInt() and 0xFF
                    offset += extensionLength
                }

                ESP_PROTOCOL -> {
                    return Ipv6TransportHeaderParseResult.Rejected(
                        Ipv6PacketRejectionReason.UNSUPPORTED_SECURITY_HEADER
                    )
                }

                else -> return Ipv6TransportHeaderParseResult.NotTransport
            }
        }

        if (routingHeaderSeen) {
            return Ipv6TransportHeaderParseResult.Rejected(Ipv6PacketRejectionReason.UNSUPPORTED_ROUTING_HEADER)
        }
        if (securityHeaderSeen) {
            return Ipv6TransportHeaderParseResult.Rejected(Ipv6PacketRejectionReason.UNSUPPORTED_SECURITY_HEADER)
        }
        if (deferredRejection != null) {
            return Ipv6TransportHeaderParseResult.Rejected(deferredRejection)
        }
        return Ipv6TransportHeaderParseResult.Transport(protocol, offset, totalLength)
    }

    private fun validateOptions(
        packet: ByteArray,
        optionsStart: Int,
        optionsEnd: Int
    ): Ipv6PacketRejectionReason? {
        var offset = optionsStart
        var unsupportedOptionSeen = false
        while (offset < optionsEnd) {
            val optionType = packet[offset].toInt() and 0xFF
            if (optionType == 0) {
                offset++
                continue
            }
            if (offset + 2 > optionsEnd) return Ipv6PacketRejectionReason.INVALID_IPV6_OPTION_LENGTH
            val optionLength = packet[offset + 1].toInt() and 0xFF
            val optionDataStart = offset + 2
            val optionEnd = optionDataStart + optionLength
            if (optionEnd > optionsEnd) return Ipv6PacketRejectionReason.INVALID_IPV6_OPTION_LENGTH
            if (optionType == 1) {
                for (index in optionDataStart until optionEnd) {
                    if (packet[index].toInt() != 0) return Ipv6PacketRejectionReason.INVALID_IPV6_OPTION
                }
            } else if (optionType ushr 6 != 0) {
                unsupportedOptionSeen = true
            }
            offset = optionEnd
        }
        return if (unsupportedOptionSeen) Ipv6PacketRejectionReason.UNSUPPORTED_IPV6_OPTION else null
    }
}
