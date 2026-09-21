package io.github.xiangwang2000.dnsshield.service

import java.net.InetAddress
import java.net.UnknownHostException
import java.util.Locale
import okhttp3.Dns

/**
 * Resolves built-in DoH hosts without sending their bootstrap lookup back through the VPN.
 *
 * Keep these addresses aligned with [DohEndpointConfiguration]. Unknown hostnames are never sent to
 * the system resolver: custom endpoints must supply their own bootstrap addresses.
 */
internal object DohBootstrapDns : Dns {
    private val builtInAddresses = DohEndpointConfiguration.builtInBootstrapAddresses.mapValues { (_, ips) ->
        addresses(*ips.toTypedArray())
    }

    override fun lookup(hostname: String): List<InetAddress> = lookup(hostname, builtInAddresses)

    fun forEndpoints(endpoints: List<DnsDohEndpoint>): Dns {
        val endpointAddresses = endpoints.associate { endpoint ->
            endpoint.hostname.lowercase(Locale.ROOT) to if (endpoint.canResolveHost) {
                endpoint.bootstrapAddresses.takeIf { it.isNotEmpty() }?.let { addresses(*it.toTypedArray()) }
                    ?: listOf(literalAddress(endpoint.hostname))
            } else {
                emptyList()
            }
        }
        val combined = builtInAddresses + endpointAddresses
        return Dns { hostname -> lookup(hostname, combined) }
    }

    private fun lookup(hostname: String, knownAddresses: Map<String, List<InetAddress>>): List<InetAddress> {
        val normalized = hostname.lowercase(Locale.ROOT)
        knownAddresses[normalized]?.let { addresses ->
            if (addresses.isNotEmpty()) return addresses
            throw UnknownHostException("No bootstrap address configured for $hostname")
        }
        if (isIpLiteral(normalized)) return listOf(literalAddress(normalized))
        throw UnknownHostException("Refusing system DNS lookup for DoH bootstrap hostname: $hostname")
    }

    private fun addresses(vararg literals: String): List<InetAddress> = literals.map(::ipv4Address)

    private fun ipv4Address(literal: String): InetAddress {
        val octets = literal.split('.')
        require(octets.size == 4)
        return InetAddress.getByAddress(ByteArray(4) { index -> octets[index].toInt().toByte() })
    }

    private fun literalAddress(literal: String): InetAddress =
        if (isIpv4Literal(literal)) ipv4Address(literal) else InetAddress.getByName(literal)
}
