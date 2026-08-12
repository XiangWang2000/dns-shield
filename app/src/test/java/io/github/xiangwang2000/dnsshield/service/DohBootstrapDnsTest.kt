package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertEquals

class DohBootstrapDnsTest {
    @Test
    fun builtInDohHostsResolveToTheirConfiguredLiteralAddresses() {
        val expected = mapOf(
            "dns.google" to listOf("8.8.8.8", "8.8.4.4"),
            "cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1"),
            "dns.adguard-dns.com" to listOf("94.140.14.14", "94.140.15.15"),
            "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112")
        )

        expected.forEach { (hostname, addresses) ->
            assertEquals(addresses, DohBootstrapDns.lookup(hostname).map { requireNotNull(it.hostAddress) })
            assertEquals(
                addresses,
                DohBootstrapDns.lookup(hostname.uppercase()).map { requireNotNull(it.hostAddress) }
            )
        }
    }
}
