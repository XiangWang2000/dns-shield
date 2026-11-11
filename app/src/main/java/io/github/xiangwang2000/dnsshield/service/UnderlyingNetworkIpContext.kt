package io.github.xiangwang2000.dnsshield.service

import java.util.Collections

/** Stable, platform-independent IP facts used to detect underlay changes. */
internal class UnderlyingNetworkIpContext private constructor(
    val linkAddresses: List<String>,
    val routes: List<String>,
    val dnsServers: List<String>,
    val nat64Prefix: String?,
    val privateDnsActive: Boolean,
    val privateDnsServerName: String?
) {
    override fun equals(other: Any?): Boolean =
        other is UnderlyingNetworkIpContext &&
            linkAddresses == other.linkAddresses &&
            routes == other.routes &&
            dnsServers == other.dnsServers &&
            nat64Prefix == other.nat64Prefix &&
            privateDnsActive == other.privateDnsActive &&
            privateDnsServerName == other.privateDnsServerName

    override fun hashCode(): Int {
        var result = linkAddresses.hashCode()
        result = 31 * result + routes.hashCode()
        result = 31 * result + dnsServers.hashCode()
        result = 31 * result + (nat64Prefix?.hashCode() ?: 0)
        result = 31 * result + privateDnsActive.hashCode()
        result = 31 * result + (privateDnsServerName?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun of(
            linkAddresses: Iterable<String>,
            routes: Iterable<String>,
            dnsServers: Iterable<String>,
            nat64Prefix: String? = null,
            privateDnsActive: Boolean = false,
            privateDnsServerName: String? = null
        ) = UnderlyingNetworkIpContext(
            immutableSortedDistinct(linkAddresses),
            immutableSortedDistinct(routes),
            immutableSortedDistinct(dnsServers),
            nat64Prefix,
            privateDnsActive,
            privateDnsServerName
        )

        private fun immutableSortedDistinct(values: Iterable<String>): List<String> =
            Collections.unmodifiableList(values.toSet().sorted())
    }
}
