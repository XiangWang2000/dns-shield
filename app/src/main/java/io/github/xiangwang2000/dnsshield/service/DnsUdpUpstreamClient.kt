package io.github.xiangwang2000.dnsshield.service

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine

internal data class DnsUdpUpstreamEndpoint(
    val address: InetAddress,
    val port: Int = 53
)

internal object DnsUdpUpstreamClient {
    private const val DEFAULT_ATTEMPT_TIMEOUT_MILLIS = 3_000L
    private const val DNS_MESSAGE_BUFFER_BYTES = DnsMessageValidator.MAX_UDP_RESPONSE_BYTES + 1

    suspend fun query(
        socket: DatagramSocket,
        query: ParsedDnsQuery,
        server: InetAddress,
        port: Int = 53,
        deadline: DnsRequestDeadline,
        attemptTimeoutMillis: Long = DEFAULT_ATTEMPT_TIMEOUT_MILLIS,
        ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
        onAttempt: () -> Unit = {},
        receiveBufferAllocator: (Int) -> ByteArray = { ByteArray(it) },
        onTimeout: () -> Unit = {},
        onAnswer: (responseCode: Int) -> Unit = {}
    ): ByteArray? {
        val startedAtNanos = System.nanoTime()
        val remainingMillis = deadline.remainingMillis(startedAtNanos)
        val timeoutMillis = minOf(remainingMillis, attemptTimeoutMillis)
        if (timeoutMillis <= 0L) return null
        val attemptDeadlineNanos = minOf(
            deadline.deadlineNanos,
            startedAtNanos + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        )

        return suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation { socket.close() }
            ioDispatcher.dispatch(continuation.context, Runnable {
                val result = runCatching {
                    queryUntilDeadline(
                        socket,
                        query,
                        server,
                        port,
                        attemptDeadlineNanos,
                        onAttempt,
                        receiveBufferAllocator,
                        onTimeout,
                        onAnswer
                    )
                }
                if (continuation.isActive) continuation.resumeWith(result)
            })
        }
    }

    suspend fun queryWithFallback(
        socket: DatagramSocket,
        query: ParsedDnsQuery,
        upstreams: List<DnsUdpUpstreamEndpoint>,
        deadline: DnsRequestDeadline,
        onAttempt: () -> Unit = {},
        onRetry: () -> Unit = {},
        tcpQuery: suspend (DnsUdpUpstreamEndpoint) -> ByteArray? = { null },
        receiveBufferAllocator: (Int) -> ByteArray = { ByteArray(it) },
        primaryBackoff: UdpPrimaryBackoff? = null,
        onTimeout: (isPrimary: Boolean) -> Unit = {},
        onAnswer: (isPrimary: Boolean) -> Unit = {},
        onPrimaryDeferred: () -> Unit = {}
    ): DnsResolutionOutcome? {
        var lastFailure: Exception? = null
        var lastTruncatedResponse: ByteArray? = null
        var preferredBackupError: DnsResolutionOutcome? = null
        var receiveBuffer: ByteArray? = null
        val primary = upstreams.firstOrNull()
        val secondary = upstreams.getOrNull(1)
        val permit = if (primary != null && secondary != null) {
            primaryBackoff?.beginQuery(primary, secondary)
        } else {
            null
        }
        val preferBackup = permit?.preferBackup == true
        var primaryAttempted = false
        var primaryTimedOut = false
        var primaryResponded = false
        var primarySucceeded = false
        var backupSucceeded = false
        var cancelled = false
        var udpSendCount = 0
        val queryReceiveBufferAllocator: (Int) -> ByteArray = { size ->
            receiveBuffer ?: receiveBufferAllocator(size).also { receiveBuffer = it }
        }
        try {
            for (attemptNumber in upstreams.indices) {
                val index = if (preferBackup && attemptNumber < 2) 1 - attemptNumber else attemptNumber
                val upstream = upstreams[index]
                val isPrimary = index == 0
                val remainingMillis = deadline.remainingMillis()
                if (remainingMillis <= 0L) return preferredBackupError

                val remainingAttempts = upstreams.size - attemptNumber
                val attemptBudgetMillis = minOf(
                    DEFAULT_ATTEMPT_TIMEOUT_MILLIS,
                    if (remainingAttempts == 1) remainingMillis else maxOf(1L, remainingMillis / remainingAttempts)
                )
                var udpResponseCode = -1
                try {
                    val response = query(
                        socket = socket,
                        query = query,
                        server = upstream.address,
                        port = upstream.port,
                        deadline = deadline,
                        attemptTimeoutMillis = attemptBudgetMillis,
                        onAttempt = {
                            onAttempt()
                            if (isPrimary) primaryAttempted = true
                            if (udpSendCount++ > 0) onRetry()
                            if (preferBackup && attemptNumber == 0 && !isPrimary) onPrimaryDeferred()
                        },
                        receiveBufferAllocator = queryReceiveBufferAllocator,
                        onTimeout = {
                            onTimeout(isPrimary)
                            if (isPrimary) primaryTimedOut = true
                        },
                        onAnswer = { responseCode ->
                            udpResponseCode = responseCode
                            onAnswer(isPrimary)
                        }
                    )
                    if (response != null) {
                        if (DnsMessageValidator.isTruncatedResponse(response, query)) {
                            if (permit?.enabled == true && isPrimary) primaryResponded = true
                            if (DnsMessageValidator.isValidResponse(response, query)) {
                                lastTruncatedResponse = response
                            }
                            if (deadline.remainingMillis() > 0L) {
                                val tcpResponse = tcpQuery(upstream)
                                if (tcpResponse != null) {
                                    val tcpResponseCode = DnsMessageValidator.validatedResponseCode(tcpResponse, query)
                                    if (tcpResponseCode >= 0) {
                                        val tcpTruncated = tcpResponse[2].toInt() and 0x02 != 0
                                        val successfulTcpOutcome = !tcpTruncated &&
                                            isSuccessfulDnsResponseCode(tcpResponseCode)
                                        if (permit?.enabled == true && !tcpTruncated &&
                                            isSuccessfulDnsResponseCode(tcpResponseCode)
                                        ) {
                                            if (isPrimary) primarySucceeded = true else backupSucceeded = true
                                        }
                                        val outcome = DnsResolutionOutcome(tcpResponse, DnsTransport.PLAINTEXT_TCP)
                                        if (preferBackup && attemptNumber == 0 && !isPrimary) {
                                            if (tcpTruncated) continue
                                            if (!successfulTcpOutcome) {
                                                preferredBackupError = outcome
                                                continue
                                            }
                                        }
                                        if (preferredBackupError != null && !successfulTcpOutcome) {
                                            return preferredBackupError
                                        }
                                        return outcome
                                    }
                                }
                            }
                        } else {
                            if (permit?.enabled == true) {
                                if (isPrimary) {
                                    primaryResponded = true
                                    if (isSuccessfulDnsResponseCode(udpResponseCode)) primarySucceeded = true
                                } else if (isSuccessfulDnsResponseCode(udpResponseCode)) {
                                    backupSucceeded = true
                                }
                            }
                            val outcome = DnsResolutionOutcome(response, DnsTransport.PLAINTEXT_UDP)
                            if (preferBackup && attemptNumber == 0 && !isPrimary &&
                                !isSuccessfulDnsResponseCode(udpResponseCode)
                            ) {
                                preferredBackupError = outcome
                            } else if (preferredBackupError != null &&
                                !isSuccessfulDnsResponseCode(udpResponseCode)
                            ) {
                                return preferredBackupError
                            } else {
                                return outcome
                            }
                        }
                    }
                } catch (exception: CancellationException) {
                    cancelled = true
                    throw exception
                } catch (exception: Exception) {
                    lastFailure = exception
                }
            }
        } finally {
            if (permit != null && primaryBackoff != null) {
                if (cancelled) {
                    primaryBackoff.abandonQuery(permit)
                } else {
                    primaryBackoff.finishQuery(
                        permit = permit,
                        primaryAttempted = primaryAttempted,
                        primaryTimedOut = primaryTimedOut,
                        primaryResponded = primaryResponded,
                        primarySucceeded = primarySucceeded,
                        backupSucceeded = backupSucceeded
                    )
                }
            }
        }
        preferredBackupError?.let { return it }
        lastTruncatedResponse?.let { return DnsResolutionOutcome(it, DnsTransport.PLAINTEXT_UDP) }
        lastFailure?.let { throw it }
        return null
    }

    /** Blocking variant retained for precise socket-level tests. */
    fun queryBlocking(
        socket: DatagramSocket,
        query: ParsedDnsQuery,
        server: InetAddress,
        port: Int = 53,
        timeoutMillis: Int = DEFAULT_ATTEMPT_TIMEOUT_MILLIS.toInt()
    ): ByteArray? {
        if (timeoutMillis <= 0) return null
        val deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis.toLong())
        return queryUntilDeadline(socket, query, server, port, deadlineNanos)
    }

    private fun queryUntilDeadline(
        socket: DatagramSocket,
        query: ParsedDnsQuery,
        server: InetAddress,
        port: Int,
        deadlineNanos: Long,
        onAttempt: () -> Unit = {},
        receiveBufferAllocator: (Int) -> ByteArray = { ByteArray(it) },
        onTimeout: () -> Unit = {},
        onAnswer: (responseCode: Int) -> Unit = {}
    ): ByteArray? {
        if (deadlineNanos - System.nanoTime() <= 0L) return null

        socket.disconnect()
        socket.connect(server, port)
        val upstreamQuery = DnsMessageValidator.prepareUpstreamQuery(query)
        socket.send(DatagramPacket(upstreamQuery, upstreamQuery.size, server, port))
        onAttempt()

        val buffer = receiveBufferAllocator(DNS_MESSAGE_BUFFER_BYTES).also {
            check(it.size == DNS_MESSAGE_BUFFER_BYTES)
        }
        while (true) {
            val remainingNanos = deadlineNanos - System.nanoTime()
            if (remainingNanos <= 0L) {
                onTimeout()
                return null
            }
            val remainingMillis = ((remainingNanos + 999_999L) / 1_000_000L)
                .coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
            socket.soTimeout = remainingMillis

            val responsePacket = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(responsePacket)
            } catch (_: SocketTimeoutException) {
                onTimeout()
                return null
            }

            val response = responsePacket.data.copyOfRange(
                responsePacket.offset,
                responsePacket.offset + responsePacket.length
            )
            if (responsePacket.length >= buffer.size) {
                if (DnsMessageValidator.isTruncatedResponse(response, query)) return response
                continue
            }
            if (DnsMessageValidator.isTruncatedResponse(response, query)) return response
            if (response.size <= query.maxUdpResponseBytes) {
                val responseCode = DnsMessageValidator.validatedResponseCode(response, query)
                if (responseCode >= 0) {
                    onAnswer(responseCode)
                    return response
                }
            }
        }
    }

    private fun isSuccessfulDnsResponseCode(responseCode: Int): Boolean = responseCode == 0 || responseCode == 3
}
