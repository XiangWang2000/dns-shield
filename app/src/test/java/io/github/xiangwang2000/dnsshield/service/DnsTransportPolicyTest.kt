package io.github.xiangwang2000.dnsshield.service

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

class DnsTransportPolicyTest {
    @Test
    fun strictModeNeverCallsUdpAfterEncryptedEndpointsFailOrAreInBackoff() = runBlocking {
        var encryptedAttempts = 0
        var udpAttempts = 0
        val endpoints = listOf(
            endpoint("https://one.example/dns-query", "one.example", "192.0.2.1"),
            endpoint("https://two.example/dns-query", "two.example", "192.0.2.2")
        )

        val result = DnsTransportPolicy.resolve(
            allowPlaintextFallback = false,
            endpoints = endpoints,
            deadline = newDeadline(),
            dohQuery = {
                encryptedAttempts++
                null // Includes HTTP, certificate, body-validation and backoff failures.
            },
            udpQuery = {
                udpAttempts++
                byteArrayOf(1)
            }
        )

        assertEquals(2, encryptedAttempts)
        assertEquals(0, udpAttempts)
        assertSame(DnsTransport.UNAVAILABLE, result.transport)
    }

    @Test
    fun encryptedSecondaryIsTriedBeforePlaintextFallback() = runBlocking {
        val expected = byteArrayOf(9, 8, 7)
        val attempted = mutableListOf<String>()
        var udpAttempts = 0

        val result = DnsTransportPolicy.resolve(
            allowPlaintextFallback = false,
            endpoints = listOf(
                endpoint("https://primary.example/dns-query", "primary.example", "192.0.2.1"),
                endpoint("https://secondary.example/dns-query", "secondary.example", "192.0.2.2")
            ),
            deadline = newDeadline(),
            dohQuery = { endpoint ->
                attempted += endpoint.url
                if (endpoint.hostname == "secondary.example") expected else null
            },
            udpQuery = {
                udpAttempts++
                null
            }
        )

        assertEquals(
            listOf("https://primary.example/dns-query", "https://secondary.example/dns-query"),
            attempted
        )
        assertEquals(0, udpAttempts)
        assertSame(DnsTransport.ENCRYPTED_HTTPS, result.transport)
        kotlin.test.assertContentEquals(expected, result.response)
    }

    @Test
    fun strictCustomHostnameWithoutBootstrapFailsClosedWithoutStartingTransport() = runBlocking {
        var encryptedAttempts = 0
        var udpAttempts = 0
        val endpoint = DnsDohEndpoint(
            url = "https://custom.example/dns-query",
            hostname = "custom.example",
            bootstrapAddresses = emptyList(),
            isCustom = true
        )

        val result = DnsTransportPolicy.resolve(
            allowPlaintextFallback = false,
            endpoints = listOf(endpoint),
            deadline = newDeadline(),
            dohQuery = {
                encryptedAttempts++
                byteArrayOf(1)
            },
            udpQuery = {
                udpAttempts++
                byteArrayOf(1)
            }
        )

        assertEquals(0, encryptedAttempts)
        assertEquals(0, udpAttempts)
        assertSame(DnsTransport.UNAVAILABLE, result.transport)
    }

    @Test
    fun preferredModeFallsBackToUdpOnlyAfterEncryptedEndpointsFail() = runBlocking {
        var udpAttempts = 0

        val result = DnsTransportPolicy.resolve(
            allowPlaintextFallback = true,
            endpoints = listOf(endpoint("https://one.example/dns-query", "one.example", "192.0.2.1")),
            deadline = newDeadline(),
            dohQuery = { null },
            udpQuery = {
                udpAttempts++
                byteArrayOf(1, 2)
            }
        )

        assertEquals(1, udpAttempts)
        assertSame(DnsTransport.PLAINTEXT_UDP, result.transport)
    }

    private fun endpoint(url: String, hostname: String, bootstrap: String) =
        DnsDohEndpoint(url, hostname, listOf(bootstrap), isCustom = true)

    private fun newDeadline() = DnsRequestDeadline.fromReceivedAt(System.nanoTime())
}
