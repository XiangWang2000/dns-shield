package io.github.xiangwang2000.dnsshield.service

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DnsTransportPolicyTest {
    @Test
    fun strictModeNeverCallsUdpAfterEncryptedEndpointsFailOrAreInBackoff() = runBlocking {
        var encryptedAttempts = 0
        var udpAttempts = 0
        var tcpAttempts = 0
        val endpoints = listOf(
            endpoint("https://one.example/dns-query", "one.example", "192.0.2.1"),
            endpoint("https://two.example/dns-query", "two.example", "192.0.2.2")
        )

        val result = DnsTransportPolicy.resolve(
            allowPlaintextFallback = false,
            endpoints = endpoints,
            deadline = newDeadline(),
            dohQuery = { _, _ ->
                encryptedAttempts++
                null // Includes HTTP, certificate, body-validation and backoff failures.
            },
            plaintextQuery = {
                udpAttempts++
                tcpAttempts++
                DnsResolutionOutcome(byteArrayOf(1), DnsTransport.PLAINTEXT_TCP)
            }
        )

        assertEquals(2, encryptedAttempts)
        assertEquals(0, udpAttempts)
        assertEquals(0, tcpAttempts)
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
            dohQuery = { endpoint, _ ->
                attempted += endpoint.url
                if (endpoint.hostname == "secondary.example") expected else null
            },
            plaintextQuery = {
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
            dohQuery = { _, _ ->
                encryptedAttempts++
                byteArrayOf(1)
            },
            plaintextQuery = {
                udpAttempts++
                DnsResolutionOutcome(byteArrayOf(1), DnsTransport.PLAINTEXT_UDP)
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
            dohQuery = { _, _ -> null },
            plaintextQuery = {
                udpAttempts++
                DnsResolutionOutcome(byteArrayOf(1, 2), DnsTransport.PLAINTEXT_UDP)
            }
        )

        assertEquals(1, udpAttempts)
        assertSame(DnsTransport.PLAINTEXT_UDP, result.transport)
    }

    @Test
    fun preferredModeKeepsTcpFallbackAsTheActualTransport() = runBlocking {
        val result = DnsTransportPolicy.resolve(
            allowPlaintextFallback = true,
            endpoints = emptyList(),
            deadline = newDeadline(),
            dohQuery = { _, _ -> null },
            plaintextQuery = {
                DnsResolutionOutcome(byteArrayOf(3, 4), DnsTransport.PLAINTEXT_TCP)
            }
        )

        assertSame(DnsTransport.PLAINTEXT_TCP, result.transport)
        kotlin.test.assertContentEquals(byteArrayOf(3, 4), result.response)
    }

    @Test
    fun attemptBudgetSharesDeadlineAcrossUniqueEndpointsAndPlaintextFallback() = runBlocking {
        var nowNanos = 0L
        val deadline = DnsRequestDeadline.fromReceivedAt(nowNanos, timeoutMillis = 6_000)
        val primary = endpoint("https://resolver.example/dns-query", "resolver.example", "192.0.2.1")
        val duplicate = primary.copy(isCustom = false)
        val alternateBootstrap = primary.copy(bootstrapAddresses = listOf("192.0.2.2"))
        val budgets = mutableListOf<Pair<List<String>, Long>>()
        var fallbackRemainingMillis = 0L

        val result = DnsTransportPolicy.resolve(
            allowPlaintextFallback = true,
            endpoints = listOf(primary, duplicate, alternateBootstrap),
            deadline = deadline,
            nowNanos = { nowNanos },
            dohQuery = { endpoint, attemptTimeoutMillis ->
                budgets += endpoint.bootstrapAddresses to attemptTimeoutMillis
                nowNanos += java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(attemptTimeoutMillis)
                null
            },
            plaintextQuery = {
                fallbackRemainingMillis = deadline.remainingMillis(nowNanos)
                DnsResolutionOutcome(byteArrayOf(1), DnsTransport.PLAINTEXT_UDP)
            }
        )

        assertEquals(
            listOf(listOf("192.0.2.1") to 2_000L, listOf("192.0.2.2") to 2_000L),
            budgets
        )
        assertEquals(2_000L, fallbackRemainingMillis)
        assertSame(DnsTransport.PLAINTEXT_UDP, result.transport)
    }

    @Test
    fun parentCancellationPropagatesWithoutStartingBackupOrFallback() = runBlocking {
        val enteredPrimary = CompletableDeferred<Unit>()
        var backupAttempts = 0
        var fallbackAttempts = 0
        val resolution = async {
            DnsTransportPolicy.resolve(
                allowPlaintextFallback = true,
                endpoints = listOf(
                    endpoint("https://primary.example/dns-query", "primary.example", "192.0.2.1"),
                    endpoint("https://backup.example/dns-query", "backup.example", "192.0.2.2")
                ),
                deadline = newDeadline(),
                dohQuery = { endpoint, _ ->
                    if (endpoint.hostname == "primary.example") {
                        enteredPrimary.complete(Unit)
                        awaitCancellation()
                    }
                    backupAttempts++
                    byteArrayOf(1)
                },
                plaintextQuery = {
                    fallbackAttempts++
                    null
                }
            )
        }

        enteredPrimary.await()
        resolution.cancelAndJoin()

        assertTrue(resolution.isCancelled)
        assertEquals(0, backupAttempts)
        assertEquals(0, fallbackAttempts)
    }

    private fun endpoint(url: String, hostname: String, bootstrap: String) =
        DnsDohEndpoint(url, hostname, listOf(bootstrap), isCustom = true)

    private fun newDeadline() = DnsRequestDeadline.fromReceivedAt(System.nanoTime())
}
