package io.github.xiangwang2000.dnsshield.service

import kotlinx.coroutines.CancellationException

internal enum class DnsTransport {
    ENCRYPTED_HTTPS,
    PLAINTEXT_UDP,
    PLAINTEXT_TCP,
    SYSTEM,
    UNAVAILABLE
}

internal data class DnsResolutionOutcome(
    val response: ByteArray?,
    val transport: DnsTransport,
    val endpointUrl: String? = null
)

/** A valid-shaped SIG(0) reply covers the exact query sent on the wire. */
internal class DnsSig0RetryRequired(
    val upstream: DnsUdpUpstreamEndpoint,
    val transport: DnsTransport,
    val attemptDeadlineNanos: Long
) : Exception("A SIG(0) response requires the original DNS query")

internal inline fun finishPlaintextDnsResponse(
    response: ByteArray,
    query: ParsedDnsQuery,
    sentQuery: ByteArray,
    hasSig0: Boolean,
    requireSig0Response: Boolean,
    retryRequired: () -> DnsSig0RetryRequired
): ByteArray? {
    if (hasSig0) {
        if (!sentQuery.contentEquals(query.wire)) throw retryRequired()
        return response
    }
    if (requireSig0Response) return null
    return DnsMessageValidator.restoreClientTransactionId(response, query)
}

internal object DnsTransportPolicy {
    suspend fun resolve(
        allowPlaintextFallback: Boolean,
        endpoints: List<DnsDohEndpoint>,
        deadline: DnsRequestDeadline,
        nowNanos: () -> Long = System::nanoTime,
        dohQuery: suspend (DnsDohEndpoint, Long) -> ByteArray?,
        plaintextQuery: suspend () -> DnsResolutionOutcome?
    ): DnsResolutionOutcome {
        val candidates = endpoints.asSequence()
            .filter { it.canResolveHost }
            .distinctBy { it.url to it.bootstrapAddresses }
            .toList()

        for ((index, endpoint) in candidates.withIndex()) {
            val remainingMillis = deadline.remainingMillis(nowNanos())
            if (remainingMillis <= 0L) break
            val stagesRemaining = candidates.size - index + if (allowPlaintextFallback) 1 else 0
            val attemptTimeoutMillis = remainingMillis / stagesRemaining
            if (attemptTimeoutMillis <= 0L) continue

            val response = try {
                dohQuery(endpoint, attemptTimeoutMillis)
            } catch (exception: CancellationException) {
                throw exception
            } catch (_: Exception) {
                null
            }
            if (response != null) {
                return DnsResolutionOutcome(response, DnsTransport.ENCRYPTED_HTTPS, endpoint.url)
            }
        }

        if (allowPlaintextFallback && deadline.remainingMillis(nowNanos()) > 0L) {
            val response = try {
                plaintextQuery()
            } catch (exception: CancellationException) {
                throw exception
            } catch (_: Exception) {
                null
            }
            if (response?.response != null) return response
        }

        return DnsResolutionOutcome(null, DnsTransport.UNAVAILABLE)
    }
}
