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

    /** Bind one endpoint's host to its configured addresses; another endpoint cannot override it. */
    fun forEndpoint(endpoint: DnsDohEndpoint): Dns {
        val configured = if (endpoint.canResolveHost) {
            endpoint.bootstrapAddresses.takeIf { it.isNotEmpty() }?.let { addresses(*it.toTypedArray()) }
                ?: listOf(literalAddress(endpoint.hostname))
        } else {
            emptyList()
        }
        val combined = builtInAddresses + (endpoint.hostname.lowercase(Locale.ROOT) to configured)
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

    private fun addresses(vararg literals: String): List<InetAddress> = literals.map(::literalAddress)

    private fun literalAddress(literal: String): InetAddress =
        IpAddressLiteral.parse(literal)?.toInetAddress()
            ?: throw IllegalArgumentException("Invalid numeric bootstrap address: $literal")
}
