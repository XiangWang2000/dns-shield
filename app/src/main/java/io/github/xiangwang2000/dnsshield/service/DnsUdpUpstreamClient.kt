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
    private const val DNS_MESSAGE_BUFFER_BYTES = DnsMessageValidator.MAX_DNS_MESSAGE_BYTES + 1

    suspend fun query(
        socket: DatagramSocket,
        query: ParsedDnsQuery,
        server: InetAddress,
        port: Int = 53,
        deadline: DnsRequestDeadline,
        attemptTimeoutMillis: Long = DEFAULT_ATTEMPT_TIMEOUT_MILLIS,
        ioDispatcher: CoroutineDispatcher = Dispatchers.IO
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
                    queryUntilDeadline(socket, query, server, port, attemptDeadlineNanos)
                }
                if (continuation.isActive) continuation.resumeWith(result)
            })
        }
    }

    suspend fun queryWithFallback(
        socket: DatagramSocket,
        query: ParsedDnsQuery,
        upstreams: List<DnsUdpUpstreamEndpoint>,
        deadline: DnsRequestDeadline
    ): ByteArray? {
        var lastFailure: Exception? = null
        upstreams.forEachIndexed { index, upstream ->
            val remainingMillis = deadline.remainingMillis()
            if (remainingMillis <= 0L) return null

            val remainingAttempts = upstreams.size - index
            val attemptBudgetMillis = minOf(
                DEFAULT_ATTEMPT_TIMEOUT_MILLIS,
                if (remainingAttempts == 1) remainingMillis else maxOf(1L, remainingMillis / remainingAttempts)
            )
            try {
                val response = query(
                    socket = socket,
                    query = query,
                    server = upstream.address,
                    port = upstream.port,
                    deadline = deadline,
                    attemptTimeoutMillis = attemptBudgetMillis
                )
                if (response != null) return response
            } catch (exception: CancellationException) {
                throw exception
            } catch (exception: Exception) {
                lastFailure = exception
            }
        }
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
        deadlineNanos: Long
    ): ByteArray? {
        if (deadlineNanos - System.nanoTime() <= 0L) return null

        socket.disconnect()
        socket.connect(server, port)
        val upstreamQuery = DnsMessageValidator.prepareUpstreamQuery(query)
        socket.send(DatagramPacket(upstreamQuery, upstreamQuery.size, server, port))

        val buffer = ByteArray(DNS_MESSAGE_BUFFER_BYTES)
        while (true) {
            val remainingNanos = deadlineNanos - System.nanoTime()
            if (remainingNanos <= 0L) return null
            val remainingMillis = ((remainingNanos + 999_999L) / 1_000_000L)
                .coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
            socket.soTimeout = remainingMillis

            val responsePacket = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(responsePacket)
            } catch (_: SocketTimeoutException) {
                return null
            }

            val response = responsePacket.data.copyOfRange(
                responsePacket.offset,
                responsePacket.offset + responsePacket.length
            )
            if (response.size <= query.maxUdpResponseBytes && DnsMessageValidator.isValidResponse(response, query)) {
                return response
            }
        }
    }
}
