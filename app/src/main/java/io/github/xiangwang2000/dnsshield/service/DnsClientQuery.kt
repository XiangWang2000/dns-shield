package io.github.xiangwang2000.dnsshield.service

/** DNS semantics shared by UDP envelopes and TCP streams. */
internal interface DnsClientQuery {
    val payload: ByteArray
    val query: ParsedDnsQuery
}

internal data class ParsedTcpDnsQuery(
    override val payload: ByteArray,
    override val query: ParsedDnsQuery
) : DnsClientQuery
