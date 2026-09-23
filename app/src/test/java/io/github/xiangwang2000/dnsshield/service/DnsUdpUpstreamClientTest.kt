package io.github.xiangwang2000.dnsshield.service

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsUdpUpstreamClientTest {
    @Test
    fun ignoresWrongSourceIdAndQuestionUntilAValidResponseArrives() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val wrongSource = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val serverFailure = AtomicReference<Throwable?>()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val expectedResponse = DnsTestMessages.response(queryBytes)

        val fakeUpstream = thread(name = "fake-dns-upstream") {
            try {
                val request = DatagramPacket(ByteArray(4096), 4096)
                server.receive(request)
                wrongSource.send(DatagramPacket(expectedResponse, expectedResponse.size, request.address, request.port))

                val wrongId = expectedResponse.copyOf().also { it[1] = (it[1].toInt() xor 1).toByte() }
                server.send(DatagramPacket(wrongId, wrongId.size, request.address, request.port))

                val wrongQuestion = DnsTestMessages.response(queryBytes, name = "other.example")
                server.send(DatagramPacket(wrongQuestion, wrongQuestion.size, request.address, request.port))
                server.send(DatagramPacket(expectedResponse, expectedResponse.size, request.address, request.port))
            } catch (failure: Throwable) {
                serverFailure.set(failure)
            }
        }

        try {
            val response = DnsUdpUpstreamClient.query(client, query, loopback, server.localPort, 2000)
            assertContentEquals(expectedResponse, response)
            fakeUpstream.join(2000)
            assertTrue(!fakeUpstream.isAlive)
            assertNull(serverFailure.get())
        } finally {
            client.close()
            wrongSource.close()
            server.close()
            fakeUpstream.join(2000)
        }
    }

    @Test
    fun returnsNullWhenOnlyMalformedResponsesArrive() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query

        val fakeUpstream = thread {
            val request = DatagramPacket(ByteArray(4096), 4096)
            server.receive(request)
            val malformed = byteArrayOf(0x12, 0x34)
            server.send(DatagramPacket(malformed, malformed.size, request.address, request.port))
        }

        try {
            assertNull(DnsUdpUpstreamClient.query(client, query, loopback, server.localPort, 150))
            fakeUpstream.join(1000)
            assertTrue(!fakeUpstream.isAlive)
        } finally {
            client.close()
            server.close()
            fakeUpstream.join(1000)
        }
    }

    @Test
    fun rejectsDatagramsLargerThanTheDnsMessageLimit() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query(edns = true, udpPayloadSize = DnsMessageValidator.MAX_DNS_MESSAGE_BYTES)
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val fullLengthResponse = DnsTestMessages.responseWithOptPadding(
            queryBytes,
            targetSize = DnsMessageValidator.MAX_DNS_MESSAGE_BYTES,
            udpPayloadSize = DnsMessageValidator.MAX_DNS_MESSAGE_BYTES
        )
        kotlin.test.assertTrue(DnsMessageValidator.isValidResponse(fullLengthResponse, query))
        val oversizedResponse = fullLengthResponse + byteArrayOf(0)

        val fakeUpstream = thread {
            val request = DatagramPacket(ByteArray(4096), 4096)
            server.receive(request)
            server.send(DatagramPacket(oversizedResponse, oversizedResponse.size, request.address, request.port))
        }

        try {
            assertNull(DnsUdpUpstreamClient.query(client, query, loopback, server.localPort, 150))
            fakeUpstream.join(1000)
            assertTrue(!fakeUpstream.isAlive)
        } finally {
            client.close()
            server.close()
            fakeUpstream.join(1000)
        }
    }

    @Test
    fun rejectsUdpResponsesLargerThanTheRequestorsAdvertisedPayload() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query(edns = true, udpPayloadSize = 512)
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val oversizedResponse = DnsTestMessages.responseWithOptPadding(queryBytes, targetSize = 513, udpPayloadSize = 512)
        assertTrue(DnsMessageValidator.isValidResponse(oversizedResponse, query))

        val fakeUpstream = thread {
            val request = DatagramPacket(ByteArray(4096), 4096)
            server.receive(request)
            server.send(DatagramPacket(oversizedResponse, oversizedResponse.size, request.address, request.port))
        }

        try {
            assertNull(DnsUdpUpstreamClient.query(client, query, loopback, server.localPort, 150))
            fakeUpstream.join(1000)
            assertTrue(!fakeUpstream.isAlive)
        } finally {
            client.close()
            server.close()
            fakeUpstream.join(1000)
        }
    }

    @Test
    fun invalidResponsesDoNotResetTheOriginalDeadline() {
        val loopback = InetAddress.getByName("127.0.0.1")
        val server = DatagramSocket(0, loopback)
        val client = DatagramSocket()
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query

        val fakeUpstream = thread {
            val request = DatagramPacket(ByteArray(4096), 4096)
            server.receive(request)
            repeat(8) { index ->
                Thread.sleep(120)
                val invalid = DnsTestMessages.response(queryBytes, transactionId = 0x4000 + index)
                server.send(DatagramPacket(invalid, invalid.size, request.address, request.port))
            }
        }

        try {
            val startedAt = System.nanoTime()
            assertNull(DnsUdpUpstreamClient.query(client, query, loopback, server.localPort, 400))
            val elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000L
            kotlin.test.assertTrue(elapsedMillis < 900, "invalid responses extended the deadline: ${elapsedMillis}ms")
            fakeUpstream.join(2000)
            assertTrue(!fakeUpstream.isAlive)
        } finally {
            client.close()
            server.close()
            fakeUpstream.join(2000)
        }
    }
}
