package io.github.xiangwang2000.dnsshield.service

import java.net.InetAddress
import java.util.Locale
import okhttp3.Dns

/**
 * Resolves built-in DoH hosts without sending their bootstrap lookup back through the VPN.
 *
 * Keep these addresses aligned with [DnsVpnService.getDoHUrl]. OkHttp still validates TLS against
 * the URL hostname, and the service retains its protected UDP fallback if an endpoint changes.
 */
internal object DohBootstrapDns : Dns {
    private val bootstrapAddresses = mapOf(
        "dns.google" to addresses("8.8.8.8", "8.8.4.4"),
        "cloudflare-dns.com" to addresses("1.1.1.1", "1.0.0.1"),
        "dns.adguard-dns.com" to addresses("94.140.14.14", "94.140.15.15"),
        "dns.quad9.net" to addresses("9.9.9.9", "149.112.112.112")
    )

    override fun lookup(hostname: String): List<InetAddress> =
        bootstrapAddresses[hostname.lowercase(Locale.ROOT)] ?: Dns.SYSTEM.lookup(hostname)

    private fun addresses(vararg literals: String): List<InetAddress> = literals.map(::ipv4Address)

    private fun ipv4Address(literal: String): InetAddress {
        val octets = literal.split('.')
        require(octets.size == 4)
        return InetAddress.getByAddress(ByteArray(4) { index -> octets[index].toInt().toByte() })
    }
}
