package io.github.xiangwang2000.dnsshield.service

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException

internal object DnsUdpUpstreamClient {
    fun query(
        socket: DatagramSocket,
        query: ParsedDnsQuery,
        server: InetAddress,
        port: Int = 53,
        timeoutMillis: Int = 3000
    ): ByteArray? {
        if (timeoutMillis <= 0) return null

        val deadlineNanos = System.nanoTime() + timeoutMillis * 1_000_000L
        socket.disconnect()
        socket.connect(server, port)
        val upstreamQuery = DnsMessageValidator.prepareUpstreamQuery(query)
        socket.send(DatagramPacket(upstreamQuery, upstreamQuery.size, server, port))

        // One extra byte makes a truncated oversized datagram fail the DNS message-size check.
        val buffer = ByteArray(DnsMessageValidator.MAX_DNS_MESSAGE_BYTES + 1)
        while (true) {
            val remainingNanos = deadlineNanos - System.nanoTime()
            if (remainingNanos <= 0) return null
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
