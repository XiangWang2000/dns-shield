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
        val dns = DohBootstrapDns.forEndpoints(listOf(endpoint))

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
