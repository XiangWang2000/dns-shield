package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertEquals

class DohBootstrapDnsTest {
    @Test
    fun builtInDohHostsResolveToTheirConfiguredLiteralAddresses() {
        val expected = mapOf(
            "dns.google" to listOf(
                "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"
            ),
            "cloudflare-dns.com" to listOf(
                "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"
            ),
            "dns.adguard-dns.com" to listOf(
                "94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"
            ),
            "dns.quad9.net" to listOf(
                "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"
            )
        )

        expected.forEach { (hostname, addresses) ->
            assertEquals(
                addresses,
                DohBootstrapDns.lookup(hostname).map {
                    requireNotNull(IpAddressLiteral.parse(requireNotNull(it.hostAddress))).normalized
                }
            )
            assertEquals(
                addresses,
                DohBootstrapDns.lookup(hostname.uppercase()).map {
                    requireNotNull(IpAddressLiteral.parse(requireNotNull(it.hostAddress))).normalized
                }
            )
        }
    }
}
