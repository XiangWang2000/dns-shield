package io.github.xiangwang2000.dnsshield.service

import java.net.UnknownHostException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DohEndpointConfigurationTest {
    @Test
    fun requiresHttpsAndValidUrlComponents() {
        assertNotNull(
            DohEndpointConfiguration.validationError(
                configuredUrl = "http://resolver.example/dns-query",
                configuredBootstrapIps = "192.0.2.1",
                strict = false
            )
        )
        assertNotNull(
            DohEndpointConfiguration.validationError(
                configuredUrl = "https://user:pass@resolver.example/dns-query",
                configuredBootstrapIps = "192.0.2.1",
                strict = false
            )
        )
        assertNull(
            DohEndpointConfiguration.validationError(
                configuredUrl = "https://resolver.example/dns-query",
                configuredBootstrapIps = "192.0.2.1, 192.0.2.2",
                strict = true
            )
        )
    }

    @Test
    fun strictCustomHostnameNeedsBootstrapAndRejectsNonLiteralBootstrap() {
        assertNotNull(
            DohEndpointConfiguration.validationError(
                configuredUrl = "https://resolver.example/dns-query",
                configuredBootstrapIps = "",
                strict = true
            )
        )
        assertNotNull(
            DohEndpointConfiguration.validationError(
                configuredUrl = "https://resolver.example/dns-query",
                configuredBootstrapIps = "bootstrap.example",
                strict = true
            )
        )
        assertNull(
            DohEndpointConfiguration.validationError(
                configuredUrl = "https://192.0.2.53/dns-query",
                configuredBootstrapIps = "",
                strict = true
            )
        )
        assertNull(
            DohEndpointConfiguration.validationError(
                configuredUrl = "https://resolver.example/dns-query",
                configuredBootstrapIps = "192.0.2.1 2001:db8::1",
                strict = true
            )
        )
        assertNotNull(
            DohEndpointConfiguration.validationError(
                configuredUrl = "https://resolver.example/dns-query",
                configuredBootstrapIps = "[2001:db8::1]",
                strict = true
            )
        )
        assertNotNull(
            DohEndpointConfiguration.validationError(
                configuredUrl = "https://resolver.example/dns-query",
                configuredBootstrapIps = "fe80::1%wlan0",
                strict = true
            )
        )
    }

    @Test
    fun bootstrapListsNormalizeAndDeduplicateBothAddressFamilies() {
        val addresses = DohEndpointConfiguration.parseBootstrapIpAddresses(
            " 192.000.002.001, 2001:0DB8:0:0:0:0:0:1 192.0.2.1 ::ffff:192.0.2.1,::ffff:c000:201 "
        )

        assertEquals(listOf("192.0.2.1", "2001:db8::1", "::ffff:c000:201"), addresses)
        assertNull(DohEndpointConfiguration.parseBootstrapIpAddresses("resolver.example"))
        assertNull(DohEndpointConfiguration.parseBootstrapIpAddresses("https://192.0.2.1"))
    }

    @Test
    fun ipv6LiteralDohUrlRetainsHttpsUrlAndResolvesWithoutBootstrap() {
        val configuredUrl = "https://[2001:db8::1]/dns-query"
        assertNull(DohEndpointConfiguration.validationError(configuredUrl, "", strict = true))
        assertNotNull(
            DohEndpointConfiguration.validationError(
                configuredUrl = "http://[2001:db8::1]/dns-query",
                configuredBootstrapIps = "",
                strict = true
            )
        )
        val endpoint = requireNotNull(
            DohEndpointConfiguration.endpoint(
                configuredUrl = configuredUrl,
                configuredBootstrapIps = "",
                resolverIp = "203.0.113.53"
            )
        )

        assertEquals(configuredUrl, endpoint.url)
        assertEquals("2001:db8::1", endpoint.hostname)
        assertTrue(endpoint.canResolveHost)
        val address = DohBootstrapDns.forEndpoint(endpoint).lookup(endpoint.hostname).single()
        assertTrue(address is java.net.Inet6Address)
        assertEquals("2001:db8::1", IpAddressLiteral.parse(requireNotNull(address.hostAddress))?.normalized)
    }

    @Test
    fun customBootstrapIsUsedAndUnknownHostsAreNeverSentToSystemDns() {
        val endpoint = requireNotNull(
            DohEndpointConfiguration.endpoint(
                configuredUrl = "https://resolver.example/dns-query",
                configuredBootstrapIps = "192.0.2.1, 192.0.2.2",
                resolverIp = "203.0.113.53"
            )
        )
        val dns = DohBootstrapDns.forEndpoint(endpoint)

        assertEquals(
            listOf("192.0.2.1", "192.0.2.2"),
            dns.lookup("RESOLVER.EXAMPLE").map { requireNotNull(it.hostAddress) }
        )
        assertFailsWith<UnknownHostException> { dns.lookup("unconfigured.example") }
    }

    @Test
    fun builtInSecondaryIpGetsItsOwnEncryptedEndpoint() {
        val server = io.github.xiangwang2000.dnsshield.data.DnsServer(
            name = "Built-in",
            primaryIp = "9.9.9.9",
            secondaryIp = "149.112.112.112"
        )

        val endpoints = DohEndpointConfiguration.endpoints(server)

        assertEquals(2, endpoints.size)
        assertTrue(endpoints.all { it.url == "https://dns.quad9.net/dns-query" })
        assertTrue(endpoints.all { it.canResolveHost })
    }

    @Test
    fun builtInIpv6ProviderAliasesKeepTheirExistingEncryptedProfiles() {
        val expectedUrls = mapOf(
            "2001:4860:4860::8888" to "https://dns.google/dns-query",
            "2001:4860:4860::8844" to "https://dns.google/dns-query",
            "2606:4700:4700::1111" to "https://cloudflare-dns.com/dns-query",
            "2606:4700:4700::1001" to "https://cloudflare-dns.com/dns-query",
            "2a10:50c0::ad1:ff" to "https://dns.adguard-dns.com/dns-query",
            "2a10:50c0::ad2:ff" to "https://dns.adguard-dns.com/dns-query",
            "2620:fe::fe" to "https://dns.quad9.net/dns-query",
            "2620:fe::9" to "https://dns.quad9.net/dns-query"
        )

        expectedUrls.forEach { (ip, url) ->
            assertTrue(isIpLiteral(ip))
            assertEquals(url, DohEndpointConfiguration.defaultUrlForIp(ip))
            val endpoint = requireNotNull(DohEndpointConfiguration.endpoint(null, null, ip))
            assertEquals(url, endpoint.url)
            assertTrue(endpoint.canResolveHost)
            assertTrue(endpoint.bootstrapAddresses.contains(ip))
        }
        assertEquals(
            expectedUrls.getValue("2001:4860:4860::8888"),
            DohEndpointConfiguration.defaultUrlForIp("2001:4860:4860:0:0:0:0:8888")
        )
    }

    @Test
    fun strictModeRequiresAtLeastOneUsableEncryptedEndpoint() {
        val unknownResolver = io.github.xiangwang2000.dnsshield.data.DnsServer(
            name = "Custom",
            primaryIp = "203.0.113.53",
            secondaryIp = null
        )
        val builtInResolver = unknownResolver.copy(primaryIp = "1.1.1.1")

        assertFalse(DohEndpointConfiguration.hasUsableEncryptedEndpoint(unknownResolver))
        assertTrue(DohEndpointConfiguration.hasUsableEncryptedEndpoint(builtInResolver))
        assertTrue(
            DohEndpointConfiguration.hasUsableEncryptedEndpoint(
                primaryIp = "203.0.113.53",
                secondaryIp = null,
                primaryDohUrl = "https://192.0.2.53/dns-query",
                primaryDohBootstrapIps = null,
                secondaryDohUrl = null,
                secondaryDohBootstrapIps = null
            )
        )
    }
}
