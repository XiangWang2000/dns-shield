package io.github.xiangwang2000.dnsshield.service

import android.net.Network
import android.os.Build
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyAssembly
import io.github.xiangwang2000.dnsshield.data.DnsResolverMode
import io.github.xiangwang2000.dnsshield.data.DnsServer
import java.io.IOException
import java.net.DatagramSocket
import java.net.Socket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient

/** Captured by the service under its DNS state lock for one admitted query. */
internal data class DnsStateSnapshot(
    val server: DnsServer,
    val dohEndpoints: List<DnsDohEndpoint>,
    val udpEndpoints: List<DnsUdpUpstreamEndpoint>,
    val udpPrimaryBackoff: UdpPrimaryBackoff,
    val resolverGeneration: Int,
    val underlyingNetworkGeneration: Long,
    val systemDnsNetwork: Network?,
    val policyAssembly: DomainPolicyAssembly
)


/** Dispatches one query against a captured resolver configuration and a shared deadline. */
internal class DnsUpstreamResolver(
    private val plaintextFallbackFence: DnsPlaintextFallbackFence,
    private val protectUdpSocket: (DatagramSocket) -> Boolean,
    private val protectTcpSocket: (Socket) -> Boolean,
    private val getDohClient: (List<DnsDohEndpoint>, DnsDohEndpoint) -> OkHttpClient,
    private val isCurrentDnsState: (DnsStateSnapshot) -> Boolean
) {
    private val dohFailureBackoff = DohFailureBackoff()

    fun resetBackoff(resolverGeneration: Int, networkGeneration: Long) {
        dohFailureBackoff.resetForGeneration(DohFailureBackoff.Generation(resolverGeneration, networkGeneration))
    }

    suspend fun resolve(
        query: ParsedDnsQuery,
        dnsState: DnsStateSnapshot,
        deadline: DnsRequestDeadline,
        request: DnsDiagnosticMetrics.Request
    ): DnsResolutionOutcome {
        return if (dnsState.server.resolverMode == DnsResolverMode.SYSTEM) {
            val network = dnsState.systemDnsNetwork
            val response = if (
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && network != null && isCurrentDnsState(dnsState)
            ) {
                lookupSystemDns(
                    network = network,
                    query = query,
                    deadline = deadline,
                    onAttempt = { DnsLogRuntime.recordTransportAttempt(request, DnsUpstreamTransport.SYSTEM) },
                    logFailure = DnsLogRuntime::logDnsTransportFailure
                )
            } else null
            DnsResolutionOutcome(response, if (response != null) DnsTransport.SYSTEM else DnsTransport.UNAVAILABLE)
        } else {
            resolveConfiguredUpstreamQuery(query, dnsState, deadline, request)
        }
    }

    private suspend fun resolveConfiguredUpstreamQuery(
        query: ParsedDnsQuery,
        dnsState: DnsStateSnapshot,
        deadline: DnsRequestDeadline,
        request: DnsDiagnosticMetrics.Request
    ): DnsResolutionOutcome {
        val endpoints = dnsState.dohEndpoints
        val backoffGeneration = DohFailureBackoff.Generation(
            resolverGeneration = dnsState.resolverGeneration,
            networkGeneration = dnsState.underlyingNetworkGeneration
        )
        return DnsTransportPolicy.resolve(
            allowPlaintextFallback = dnsState.server.allowPlaintextFallback,
            endpoints = endpoints,
            deadline = deadline,
            dohQuery = { endpoint, attemptTimeoutMillis ->
                if (!isCurrentDnsState(dnsState) ||
                    !dohFailureBackoff.tryAcquire(endpoint, backoffGeneration)) {
                    null
                } else {
                    val response = try {
                        performDohLookup(endpoint, endpoints, query, deadline, attemptTimeoutMillis, request)
                    } catch (exception: CancellationException) {
                        dohFailureBackoff.cancelAttempt(endpoint, backoffGeneration)
                        throw exception
                    } catch (exception: Exception) {
                        dohFailureBackoff.recordFailure(endpoint, backoffGeneration)
                        DnsLogRuntime.logDnsTransportFailure(
                            "DoH request failed for ${endpoint.hostname}: ${exception.javaClass.simpleName}"
                        )
                        null
                    }
                    if (response == null) {
                        dohFailureBackoff.recordFailure(endpoint, backoffGeneration)
                    } else {
                        dohFailureBackoff.recordSuccess(endpoint, backoffGeneration)
                    }
                    response
                }
            },
            plaintextQuery = plaintext@{
                if (!dnsState.server.allowPlaintextFallback ||
                    !plaintextFallbackFence.allows(dnsState.server.id) ||
                    !isCurrentDnsState(dnsState) ||
                    deadline.remainingMillis() <= 0L
                ) {
                    null
                } else {
                    DnsLogRuntime.recordFallbackAttempt(request)
                    try {
                        if (query.wire.size > DnsMessageValidator.MAX_UDP_QUERY_BYTES) {
                            val upstreams = dnsState.udpEndpoints
                            for ((index, upstream) in upstreams.withIndex()) {
                                val remainingMillis = deadline.remainingMillis()
                                if (remainingMillis <= 0L) break
                                val attemptMillis = (remainingMillis / (upstreams.size - index)).coerceAtLeast(1L)
                                val response = try {
                                    withTimeoutOrNull(attemptMillis) {
                                        queryPlaintextTcp(query, upstream, dnsState, deadline, request)
                                    }
                                } catch (exception: IOException) {
                                    DnsLogRuntime.logDnsTransportFailure("TCP DNS request failed: ${exception.javaClass.simpleName}")
                                    null
                                }
                                if (response != null) {
                                    return@plaintext DnsResolutionOutcome(response, DnsTransport.PLAINTEXT_TCP)
                                }
                            }
                            return@plaintext null
                        }
                        openProtectedUdpSocket(dnsState, deadline).use { socket ->
                            DnsUdpUpstreamClient.queryWithFallback(
                                socket = socket,
                                query = query,
                                upstreams = dnsState.udpEndpoints,
                                deadline = deadline,
                                onAttempt = { DnsLogRuntime.recordTransportAttempt(request, DnsUpstreamTransport.UDP) },
                                onRetry = { DnsLogRuntime.recordUdpRetryAttempt(request) },
                                primaryBackoff = dnsState.udpPrimaryBackoff,
                                onTimeout = { DnsLogRuntime.recordUdpTimeout(request, it) },
                                onAnswer = { DnsLogRuntime.recordUdpAnswer(request, it) },
                                onPrimaryDeferred = { DnsLogRuntime.recordUdpPrimaryDeferred(request) },
                                tcpQuery = { queryPlaintextTcp(query, it, dnsState, deadline, request) }
                            )
                        }
                    } catch (retry: DnsSig0RetryRequired) {
                        retrySignedTransaction(query, dnsState, deadline, request, retry)
                    }
                }
            }
        )
    }

    private fun openProtectedUdpSocket(
        dnsState: DnsStateSnapshot,
        deadline: DnsRequestDeadline
    ): DatagramSocket {
        val socket = PolicyFencedDatagramSocket(
            resolverId = dnsState.server.id,
            snapshotAllowsPlaintext = dnsState.server.allowPlaintextFallback,
            fence = plaintextFallbackFence,
            currentPolicyAllowsPlaintext = {
                isCurrentDnsState(dnsState) && deadline.remainingMillis() > 0L
            }
        )
        try {
            if (!protectUdpSocket(socket)) throw IOException("Failed to protect DNS UDP socket from the VPN.")
            return socket
        } catch (exception: Throwable) {
            socket.close()
            throw exception
        }
    }

    private suspend fun retrySignedTransaction(
        query: ParsedDnsQuery,
        dnsState: DnsStateSnapshot,
        deadline: DnsRequestDeadline,
        request: DnsDiagnosticMetrics.Request,
        retry: DnsSig0RetryRequired
    ): DnsResolutionOutcome? {
        val retryDeadline = deadline.cappedAt(retry.attemptDeadlineNanos)
        if (retryDeadline.remainingMillis() <= 0L ||
            !dnsState.server.allowPlaintextFallback ||
            !plaintextFallbackFence.allows(dnsState.server.id) ||
            !isCurrentDnsState(dnsState)
        ) return null

        val response = if (retry.transport == DnsTransport.PLAINTEXT_TCP) {
            queryPlaintextTcp(query, retry.upstream, dnsState, retryDeadline, request, requireSig0Response = true)
        } else {
            val isPrimary = retry.upstream == dnsState.udpEndpoints.firstOrNull()
            openProtectedUdpSocket(dnsState, retryDeadline).use { socket ->
                DnsUdpUpstreamClient.query(
                    socket = socket,
                    query = query,
                    server = retry.upstream.address,
                    port = retry.upstream.port,
                    deadline = retryDeadline,
                    onAttempt = {
                        DnsLogRuntime.recordTransportAttempt(request, DnsUpstreamTransport.UDP)
                        DnsLogRuntime.recordUdpRetryAttempt(request)
                    },
                    onTimeout = { DnsLogRuntime.recordUdpTimeout(request, isPrimary) },
                    onAnswer = { DnsLogRuntime.recordUdpAnswer(request, isPrimary) },
                    requireSig0Response = true
                )
            }
        }
        return response?.let { DnsResolutionOutcome(it, retry.transport) }
    }

    private suspend fun queryPlaintextTcp(
        query: ParsedDnsQuery,
        upstream: DnsUdpUpstreamEndpoint,
        dnsState: DnsStateSnapshot,
        deadline: DnsRequestDeadline,
        request: DnsDiagnosticMetrics.Request,
        requireSig0Response: Boolean = false
    ): ByteArray? {
        if (!dnsState.server.allowPlaintextFallback ||
            !plaintextFallbackFence.allows(dnsState.server.id) ||
            !isCurrentDnsState(dnsState) ||
            deadline.remainingMillis() <= 0L
        ) return null

        val tcpSocket = Socket()
        return try {
            DnsTcpUpstreamClient.query(
                socket = tcpSocket,
                query = query,
                server = upstream.address,
                port = upstream.port,
                deadline = deadline,
                requireSig0Response = requireSig0Response,
                prepareSocket = { candidate ->
                    if (!plaintextFallbackFence.registerTcpSocketIfAllowed(
                            resolverId = dnsState.server.id,
                            snapshotAllowsPlaintext = dnsState.server.allowPlaintextFallback,
                            currentPolicyAllowsPlaintext = {
                                isCurrentDnsState(dnsState) && deadline.remainingMillis() > 0L
                            },
                            socket = candidate
                        )
                    ) {
                        false
                    } else if (!protectTcpSocket(candidate)) {
                        throw IOException("Failed to protect DNS TCP socket from the VPN.")
                    } else {
                        true
                    }
                },
                sendQueryFrame = { candidate, frame ->
                    plaintextFallbackFence.writeTcpFrameIfAllowed(
                        resolverId = dnsState.server.id,
                        snapshotAllowsPlaintext = dnsState.server.allowPlaintextFallback,
                        currentPolicyAllowsPlaintext = {
                            isCurrentDnsState(dnsState) && deadline.remainingMillis() > 0L
                        },
                        socket = candidate,
                        frame = frame
                    ).also { sent ->
                        if (sent) DnsLogRuntime.recordTransportAttempt(request, DnsUpstreamTransport.TCP)
                    }
                }
            )
        } finally {
            try {
                tcpSocket.close()
            } finally {
                plaintextFallbackFence.unregisterTcpSocket(
                    dnsState.server.id,
                    tcpSocket
                )
            }
        }
    }

    private suspend fun performDohLookup(
        endpoint: DnsDohEndpoint,
        resolverEndpoints: List<DnsDohEndpoint>,
        query: ParsedDnsQuery,
        deadline: DnsRequestDeadline,
        attemptTimeoutMillis: Long,
        metricsRequest: DnsDiagnosticMetrics.Request
    ): ByteArray? {
        if (deadline.remainingMillis() <= 0L) return null
        return getDohClient(resolverEndpoints, endpoint)
            .lookupDoh(
                endpointUrl = endpoint.url,
                query = query,
                deadline = deadline,
                attemptTimeoutMillis = attemptTimeoutMillis,
                onCallQueued = { DnsLogRuntime.recordTransportAttempt(metricsRequest, DnsUpstreamTransport.DOH_CALL_QUEUED) },
                logFailure = DnsLogRuntime::logDnsTransportFailure
            )
    }
}
