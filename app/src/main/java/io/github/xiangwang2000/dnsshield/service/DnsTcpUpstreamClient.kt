package io.github.xiangwang2000.dnsshield.service

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine

internal object DnsTcpUpstreamClient {
    private const val DEFAULT_ATTEMPT_TIMEOUT_MILLIS = 3_000L
    private const val LENGTH_PREFIX_BYTES = 2

    suspend fun query(
        socket: Socket,
        query: ParsedDnsQuery,
        server: InetAddress,
        port: Int = 53,
        deadline: DnsRequestDeadline,
        attemptTimeoutMillis: Long = DEFAULT_ATTEMPT_TIMEOUT_MILLIS,
        ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
        prepareSocket: (Socket) -> Boolean = { true },
        sendQueryFrame: (Socket, ByteArray) -> Boolean = { candidate, frame ->
            candidate.getOutputStream().apply {
                write(frame)
                flush()
            }
            true
        }
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
            continuation.invokeOnCancellation { runCatching { socket.close() } }
            ioDispatcher.dispatch(continuation.context, Runnable {
                if (!continuation.isActive) return@Runnable
                val result = runCatching {
                    queryUntilDeadline(
                        socket,
                        query,
                        server,
                        port,
                        attemptDeadlineNanos,
                        prepareSocket,
                        sendQueryFrame
                    )
                }
                if (continuation.isActive) continuation.resumeWith(result)
            })
        }
    }

    /** Blocking variant retained for precise socket-level tests. */
    fun queryBlocking(
        socket: Socket,
        query: ParsedDnsQuery,
        server: InetAddress,
        port: Int = 53,
        timeoutMillis: Int = DEFAULT_ATTEMPT_TIMEOUT_MILLIS.toInt(),
        prepareSocket: (Socket) -> Boolean = { true },
        sendQueryFrame: (Socket, ByteArray) -> Boolean = { candidate, frame ->
            candidate.getOutputStream().apply {
                write(frame)
                flush()
            }
            true
        }
    ): ByteArray? {
        if (timeoutMillis <= 0) return null
        val deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis.toLong())
        return queryUntilDeadline(socket, query, server, port, deadlineNanos, prepareSocket, sendQueryFrame)
    }

    private fun queryUntilDeadline(
        socket: Socket,
        query: ParsedDnsQuery,
        server: InetAddress,
        port: Int,
        deadlineNanos: Long,
        prepareSocket: (Socket) -> Boolean,
        sendQueryFrame: (Socket, ByteArray) -> Boolean
    ): ByteArray? {
        val upstreamQuery = DnsMessageValidator.prepareUpstreamQuery(query)
        if (upstreamQuery.size !in 12..DnsMessageValidator.MAX_DNS_MESSAGE_BYTES) return null
        // Android VpnService.protect needs an allocated descriptor before connect.
        if (!socket.isBound) socket.bind(InetSocketAddress(0))
        if (!prepareSocket(socket)) return null

        val initialTimeout = remainingTimeoutMillis(deadlineNanos) ?: return null
        try {
            socket.connect(InetSocketAddress(server, port), initialTimeout)
        } catch (_: SocketTimeoutException) {
            return null
        }
        if (remainingTimeoutMillis(deadlineNanos) == null) return null

        val framedQuery = ByteArray(LENGTH_PREFIX_BYTES + upstreamQuery.size)
        framedQuery[0] = (upstreamQuery.size ushr 8).toByte()
        framedQuery[1] = upstreamQuery.size.toByte()
        System.arraycopy(upstreamQuery, 0, framedQuery, LENGTH_PREFIX_BYTES, upstreamQuery.size)
        if (!sendQueryFrame(socket, framedQuery)) return null

        val input = socket.getInputStream()
        val lengthPrefix = ByteArray(LENGTH_PREFIX_BYTES)
        if (!readFully(input, socket, lengthPrefix, deadlineNanos)) return null
        val responseLength = readUnsignedShort(lengthPrefix, 0)
        if (responseLength !in 12..DnsMessageValidator.MAX_DNS_MESSAGE_BYTES) return null

        val response = ByteArray(responseLength)
        if (!readFully(input, socket, response, deadlineNanos)) return null
        return response.takeIf { DnsMessageValidator.isValidResponse(it, query) }
    }

    private fun readFully(
        input: java.io.InputStream,
        socket: Socket,
        output: ByteArray,
        deadlineNanos: Long
    ): Boolean {
        var offset = 0
        while (offset < output.size) {
            val remainingMillis = remainingTimeoutMillis(deadlineNanos) ?: return false
            socket.soTimeout = remainingMillis
            val read = try {
                input.read(output, offset, output.size - offset)
            } catch (_: SocketTimeoutException) {
                return false
            }
            if (read < 0) return false
            if (read > 0) offset += read
        }
        return true
    }

    private fun remainingTimeoutMillis(deadlineNanos: Long): Int? {
        val remainingNanos = deadlineNanos - System.nanoTime()
        if (remainingNanos <= 0L) return null
        return ((remainingNanos + 999_999L) / 1_000_000L)
            .coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
    }
}
