package io.github.xiangwang2000.dnsshield.service

import kotlinx.coroutines.CancellationException

internal enum class DnsTransport {
    ENCRYPTED_HTTPS,
    PLAINTEXT_UDP,
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
        dohQuery: suspend (DnsDohEndpoint) -> ByteArray?,
        udpQuery: suspend () -> ByteArray?
    ): DnsResolutionOutcome {
        for (endpoint in endpoints) {
            if (!endpoint.canResolveHost || deadline.remainingMillis() <= 0L) continue
            val response = try {
                dohQuery(endpoint)
            } catch (exception: CancellationException) {
                throw exception
            } catch (_: Exception) {
                null
            }
            if (response != null) {
                return DnsResolutionOutcome(response, DnsTransport.ENCRYPTED_HTTPS, endpoint.url)
            }
        }

        if (allowPlaintextFallback && deadline.remainingMillis() > 0L) {
            val response = try {
                udpQuery()
            } catch (exception: CancellationException) {
                throw exception
            } catch (_: Exception) {
                null
            }
            if (response != null) {
                return DnsResolutionOutcome(response, DnsTransport.PLAINTEXT_UDP)
            }
        }

        return DnsResolutionOutcome(null, DnsTransport.UNAVAILABLE)
    }
}
