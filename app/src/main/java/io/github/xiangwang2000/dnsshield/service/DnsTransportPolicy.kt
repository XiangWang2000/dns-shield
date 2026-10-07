package io.github.xiangwang2000.dnsshield.service

import kotlinx.coroutines.CancellationException

internal enum class DnsTransport {
    ENCRYPTED_HTTPS,
    PLAINTEXT_UDP,
    PLAINTEXT_TCP,
    UNAVAILABLE
}

internal data class DnsResolutionOutcome(
    val response: ByteArray?,
    val transport: DnsTransport,
    val endpointUrl: String? = null
)

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
