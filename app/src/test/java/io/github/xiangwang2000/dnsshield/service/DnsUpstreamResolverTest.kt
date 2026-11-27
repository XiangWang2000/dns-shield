package io.github.xiangwang2000.dnsshield.service

import io.github.xiangwang2000.dnsshield.blocking.CompiledBlocklistStatus
import io.github.xiangwang2000.dnsshield.blocking.DomainMatcher
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyAssembly
import io.github.xiangwang2000.dnsshield.data.DnsResolverMode
import io.github.xiangwang2000.dnsshield.data.DnsServer
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertNotSame
import kotlin.test.assertTrue

class DnsUpstreamResolverTest {
    @Test
    fun optionalUdpSig0ResponseRetriesOriginalQueryOnFreshSocketAndPreservesSignedReply() {
        val originalQuery = DnsTestMessages.query(
            name = QUERY_NAME,
            edns = true,
            udpPayloadSize = ADVERTISED_UDP_BYTES
        )
        assertFalse(assertIsValidUdpQuery(originalQuery).hasSig0)
        assertEquals(
            ADVERTISED_UDP_BYTES,
            readU16(originalQuery, DnsTestMessages.queryQuestionEnd(originalQuery) + 3)
        )
        val run = runUdpScenario(originalQuery, signRetry = true)

        assertEquals(2, run.requests.size)
        assertFalse(run.requests[0].contentEquals(originalQuery))
        assertEquals(
            DnsMessageValidator.MAX_UDP_RESPONSE_BYTES,
            readU16(run.requests[0], DnsTestMessages.queryQuestionEnd(run.requests[0]) + 3)
        )
        assertContentEquals(originalQuery, run.requests[1])
        assertEquals(DnsTransport.PLAINTEXT_UDP, run.outcome.transport)
        val returned = assertNotNull(run.outcome.response)
        assertContentEquals(run.responses[1], returned)
        assertSig0TransactionValid(run.responses[0], run.requests[0], run.keyPair)
        assertSig0TransactionValid(run.responses[1], originalQuery, run.keyPair)
        assertEquals(2, run.protectedUdpSockets.size)
        assertNotSame(run.protectedUdpSockets[0], run.protectedUdpSockets[1])
        assertTrue(run.protectedTcpSockets.isEmpty())
    }

    @Test
    fun largeEdnsPaddingQueryUsesTcpThenRetriesOriginalOnceOnFreshSocket() {
        val originalQuery = queryWithPadding(targetSize = 8_192)
        assertFalse(assertIsValidTcpQuery(originalQuery).hasSig0)
        assertEquals(
            ADVERTISED_UDP_BYTES,
            readU16(originalQuery, DnsTestMessages.queryQuestionEnd(originalQuery) + 3)
        )
        val run = runTcpScenario(originalQuery, signRetry = true)

        assertTrue(originalQuery.size > DnsMessageValidator.MAX_UDP_QUERY_BYTES)
        assertEquals(2, run.requests.size)
        assertFalse(run.requests[0].contentEquals(originalQuery))
        assertEquals(
            DnsMessageValidator.MAX_UDP_RESPONSE_BYTES,
            readU16(run.requests[0], DnsTestMessages.queryQuestionEnd(run.requests[0]) + 3)
        )
        assertContentEquals(originalQuery, run.requests[1])
        assertEquals(DnsTransport.PLAINTEXT_TCP, run.outcome.transport)
        val returned = assertNotNull(run.outcome.response)
        assertContentEquals(run.responses[1], returned)
        assertSig0TransactionValid(run.responses[0], run.requests[0], run.keyPair)
        assertSig0TransactionValid(run.responses[1], originalQuery, run.keyPair)
        assertEquals(2, run.protectedTcpSockets.size)
        assertNotSame(run.protectedTcpSockets[0], run.protectedTcpSockets[1])
        assertTrue(run.protectedUdpSockets.isEmpty())
    }

    @Test
    fun tcpSig0RetryReturnsUnavailableWhenTheOriginalQueryGetsAnUnsignedReply() {
        val originalQuery = queryWithPadding(targetSize = 8_192)
        val run = runTcpScenario(originalQuery, signRetry = false)

        assertEquals(2, run.requests.size)
        assertFalse(run.requests[0].contentEquals(originalQuery))
        assertContentEquals(originalQuery, run.requests[1])
        assertSig0TransactionValid(run.responses[0], run.requests[0], run.keyPair)
        assertFalse(DnsMessageValidator.hasSig0Response(
            run.responses[1],
            assertIsValidTcpQuery(originalQuery)
        ))
        assertNull(run.outcome.response)
        assertEquals(DnsTransport.UNAVAILABLE, run.outcome.transport)
        assertEquals(2, run.protectedTcpSockets.size)
        assertNotSame(run.protectedTcpSockets[0], run.protectedTcpSockets[1])
    }

    private data class ResolverRun(
        val outcome: DnsResolutionOutcome,
        val requests: List<ByteArray>,
        val responses: List<ByteArray>,
        val keyPair: KeyPair,
        val protectedUdpSockets: List<DatagramSocket>,
        val protectedTcpSockets: List<Socket>
    )

    private fun runUdpScenario(originalQuery: ByteArray, signRetry: Boolean): ResolverRun {
        val query = assertIsValidUdpQuery(originalQuery)
        val loopback = InetAddress.getByName("127.0.0.1")
        val upstreamSocket = DatagramSocket(0, loopback)
        val endpoint = DnsUdpUpstreamEndpoint(loopback, upstreamSocket.localPort)
        val keyPair = newEd25519KeyPair()
        val requests = CopyOnWriteArrayList<ByteArray>()
        val responses = CopyOnWriteArrayList<ByteArray>()
        val serverFailure = AtomicReference<Throwable?>()
        val listener = thread(name = "sig0-udp-upstream", isDaemon = true) {
            try {
                repeat(2) { index ->
                    val packet = DatagramPacket(
                        ByteArray(DnsMessageValidator.MAX_UDP_RESPONSE_BYTES),
                        DnsMessageValidator.MAX_UDP_RESPONSE_BYTES
                    )
                    upstreamSocket.receive(packet)
                    val wire = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    requests.add(wire)
                    val response = if (index == 1 && !signRetry) {
                        unsignedAnswer(wire)
                    } else {
                        signedTransactionResponse(wire, keyPair)
                    }
                    responses.add(response)
                    upstreamSocket.send(
                        DatagramPacket(response, response.size, packet.address, packet.port)
                    )
                }
            } catch (failure: Throwable) {
                if (!upstreamSocket.isClosed) serverFailure.compareAndSet(null, failure)
            }
        }

        val protectedUdpSockets = CopyOnWriteArrayList<DatagramSocket>()
        val protectedTcpSockets = CopyOnWriteArrayList<Socket>()
        val (resolver, state) = newResolver(endpoint, protectedUdpSockets, protectedTcpSockets)
        val receivedAtNanos = System.nanoTime()
        val deadline = DnsRequestDeadline.fromReceivedAt(receivedAtNanos, timeoutMillis = 2_000L)
        val outcome = try {
            runBlocking {
                withTimeout(2_500L) {
                    resolver.resolve(
                        query = query,
                        dnsState = state,
                        deadline = deadline,
                        request = DnsDiagnosticMetrics().begin(receivedAtNanos)
                    )
                }
            }
        } finally {
            upstreamSocket.close()
            listener.join(1_000)
        }

        assertFalse(listener.isAlive, "The UDP responder should finish after both requests.")
        serverFailure.get()?.let { throw IllegalStateException("The UDP responder failed.", it) }
        return ResolverRun(
            outcome = outcome,
            requests = requests.map { it.copyOf() },
            responses = responses.map { it.copyOf() },
            keyPair = keyPair,
            protectedUdpSockets = protectedUdpSockets.toList(),
            protectedTcpSockets = protectedTcpSockets.toList()
        )
    }

    private fun runTcpScenario(originalQuery: ByteArray, signRetry: Boolean): ResolverRun {
        val query = assertIsValidTcpQuery(originalQuery)
        val loopback = InetAddress.getByName("127.0.0.1")
        val upstreamServer = ServerSocket(0, 2, loopback)
        val endpoint = DnsUdpUpstreamEndpoint(loopback, upstreamServer.localPort)
        val keyPair = newEd25519KeyPair()
        val requests = CopyOnWriteArrayList<ByteArray>()
        val responses = CopyOnWriteArrayList<ByteArray>()
        val serverFailure = AtomicReference<Throwable?>()
        val listener = thread(name = "sig0-tcp-upstream", isDaemon = true) {
            try {
                repeat(2) { index ->
                    upstreamServer.accept().use { connection ->
                        connection.soTimeout = 2_000
                        val wire = DnsTcpFrameCodec.readFrame(connection.getInputStream())
                            ?: error("The TCP client closed before sending a DNS query.")
                        requests.add(wire)
                        val response = if (index == 1 && !signRetry) {
                            unsignedAnswer(wire)
                        } else {
                            signedTransactionResponse(wire, keyPair)
                        }
                        responses.add(response)
                        DnsTcpFrameCodec.writeFrame(connection.getOutputStream(), response)
                    }
                }
            } catch (failure: Throwable) {
                if (!upstreamServer.isClosed) serverFailure.compareAndSet(null, failure)
            }
        }

        val protectedUdpSockets = CopyOnWriteArrayList<DatagramSocket>()
        val protectedTcpSockets = CopyOnWriteArrayList<Socket>()
        val (resolver, state) = newResolver(endpoint, protectedUdpSockets, protectedTcpSockets)
        val receivedAtNanos = System.nanoTime()
        val deadline = DnsRequestDeadline.fromReceivedAt(receivedAtNanos, timeoutMillis = 2_000L)
        val outcome = try {
            runBlocking {
                withTimeout(2_500L) {
                    resolver.resolve(
                        query = query,
                        dnsState = state,
                        deadline = deadline,
                        request = DnsDiagnosticMetrics().begin(receivedAtNanos)
                    )
                }
            }
        } finally {
            upstreamServer.close()
            listener.join(1_000)
        }

        assertFalse(listener.isAlive, "The TCP responder should finish after both connections.")
        serverFailure.get()?.let { throw IllegalStateException("The TCP responder failed.", it) }
        return ResolverRun(
            outcome = outcome,
            requests = requests.map { it.copyOf() },
            responses = responses.map { it.copyOf() },
            keyPair = keyPair,
            protectedUdpSockets = protectedUdpSockets.toList(),
            protectedTcpSockets = protectedTcpSockets.toList()
        )
    }

    private fun newResolver(
        endpoint: DnsUdpUpstreamEndpoint,
        protectedUdpSockets: MutableList<DatagramSocket>,
        protectedTcpSockets: MutableList<Socket>
    ): Pair<DnsUpstreamResolver, DnsStateSnapshot> {
        val state = DnsStateSnapshot(
            server = DnsServer(
                id = TEST_RESOLVER_ID,
                name = "Local SIG(0) test resolver",
                primaryIp = requireNotNull(endpoint.address.hostAddress),
                secondaryIp = null,
                allowPlaintextFallback = true,
                resolverMode = DnsResolverMode.CONFIGURED
            ),
            dohEndpoints = emptyList(),
            udpEndpoints = listOf(endpoint),
            udpPrimaryBackoff = UdpPrimaryBackoff(),
            resolverGeneration = 1,
            underlyingNetworkGeneration = 1L,
            systemDnsNetwork = null,
            policyAssembly = DomainPolicyAssembly(
                matcher = DomainMatcher { false },
                compiledBlocklistStatus = CompiledBlocklistStatus.NotConfigured
            )
        )
        val resolver = DnsUpstreamResolver(
            plaintextFallbackFence = DnsPlaintextFallbackFence(),
            protectUdpSocket = { socket ->
                protectedUdpSockets.add(socket)
                true
            },
            protectTcpSocket = { socket ->
                protectedTcpSockets.add(socket)
                true
            },
            getDohClient = { _, _ -> error("DoH is not used by this test.") },
            isCurrentDnsState = { it === state }
        )
        return resolver to state
    }

    private fun signedTransactionResponse(queryWire: ByteArray, keyPair: KeyPair): ByteArray {
        val rawPublicKey = rawEd25519PublicKey(keyPair)
        val keyRdata = uint16(0) + byteArrayOf(3, ED25519_DNSSEC_ALGORITHM.toByte()) + rawPublicKey
        val keyRecord = resourceRecord(
            owner = DnsTestMessages.encodedName(SIGNER_NAME),
            type = KEY_RR_TYPE,
            clazz = 1,
            ttl = 300,
            rdata = keyRdata
        )

        val responseWithoutSig0 = (unsignedAnswer(queryWire) + keyRecord).also {
            writeU16(it, 10, 1)
        }
        val nowSeconds = System.currentTimeMillis() / 1_000L
        val signaturePrefix = uint16(0) +
            byteArrayOf(ED25519_DNSSEC_ALGORITHM.toByte(), 0) +
            uint32(0L) +
            uint32(nowSeconds + 240L) +
            uint32((nowSeconds - 120L).coerceAtLeast(0L)) +
            uint16(keyTag(keyRdata)) +
            DnsTestMessages.encodedName(SIGNER_NAME)
        val signatureInput = signaturePrefix + queryWire + responseWithoutSig0
        val signer = Signature.getInstance("Ed25519").apply {
            initSign(keyPair.private)
            update(signatureInput)
        }
        val sig0Record = resourceRecord(
            owner = byteArrayOf(0),
            type = SIG_RR_TYPE,
            clazz = 255,
            ttl = 0,
            rdata = signaturePrefix + signer.sign()
        )
        return (responseWithoutSig0 + sig0Record).also { writeU16(it, 10, 2) }
    }

    private fun assertSig0TransactionValid(response: ByteArray, queryWire: ByteArray, keyPair: KeyPair) {
        val answerAndAuthorityCount = readU16(response, 6) + readU16(response, 8)
        var recordOffset = DnsTestMessages.queryQuestionEnd(response)
        repeat(answerAndAuthorityCount) {
            recordOffset = nextRecordOffset(response, recordOffset)
        }

        val keyFieldsOffset = skipWireName(response, recordOffset)
        assertEquals(KEY_RR_TYPE, readU16(response, keyFieldsOffset))
        val keyDataOffset = keyFieldsOffset + DNS_RR_HEADER_BYTES
        val keyDataLength = readU16(response, keyFieldsOffset + 8)
        val keyRdata = response.copyOfRange(keyDataOffset, keyDataOffset + keyDataLength)
        assertEquals(3, keyRdata[2].toInt() and 0xFF)
        assertEquals(ED25519_DNSSEC_ALGORITHM, keyRdata[3].toInt() and 0xFF)
        assertContentEquals(rawEd25519PublicKey(keyPair), keyRdata.copyOfRange(4, keyRdata.size))
        val expectedKeyTag = keyTag(keyRdata)
        recordOffset = nextRecordOffset(response, recordOffset)

        val sigRecordOffset = recordOffset
        val sigFieldsOffset = skipWireName(response, sigRecordOffset)
        assertEquals(SIG_RR_TYPE, readU16(response, sigFieldsOffset))
        assertEquals(255, readU16(response, sigFieldsOffset + 2))
        val sigDataOffset = sigFieldsOffset + DNS_RR_HEADER_BYTES
        val sigDataLength = readU16(response, sigFieldsOffset + 8)
        val signatureOffset = sigDataOffset + sigDataLength - ED25519_SIGNATURE_BYTES
        assertTrue(signatureOffset >= sigDataOffset)
        val signaturePrefix = response.copyOfRange(sigDataOffset, signatureOffset)
        assertEquals(0, readU16(signaturePrefix, 0))
        assertEquals(ED25519_DNSSEC_ALGORITHM, signaturePrefix[2].toInt() and 0xFF)
        assertEquals(expectedKeyTag, readU16(signaturePrefix, 16))
        assertContentEquals(
            DnsTestMessages.encodedName(SIGNER_NAME),
            signaturePrefix.copyOfRange(SIG_FIXED_RDATA_BYTES, signaturePrefix.size)
        )
        assertEquals(response.size, nextRecordOffset(response, sigRecordOffset))

        val signature = response.copyOfRange(signatureOffset, sigDataOffset + sigDataLength)
        val responseWithoutSig0 = response.copyOfRange(0, sigRecordOffset).also {
            writeU16(it, 10, readU16(it, 10) - 1)
        }
        val signedData = signaturePrefix + queryWire + responseWithoutSig0
        val verifier = Signature.getInstance("Ed25519").apply {
            initVerify(keyPair.public)
            update(signedData)
        }
        assertTrue(verifier.verify(signature), "The SIG(0) must verify RFC 2931 transaction data.")
    }

    private fun unsignedAnswer(queryWire: ByteArray): ByteArray =
        DnsTestMessages.responseWithAnswer(
            query = queryWire,
            type = 1,
            data = byteArrayOf(203.toByte(), 0, 113, 7),
            ttlSeconds = 60
        )

    private fun queryWithPadding(targetSize: Int): ByteArray {
        val query = DnsTestMessages.query(
            name = QUERY_NAME,
            edns = true,
            udpPayloadSize = ADVERTISED_UDP_BYTES
        )
        require(targetSize > query.size + 4)
        val optionOffset = query.size
        val paddingLength = targetSize - optionOffset - 4
        val paddedQuery = query.copyOf(targetSize)
        val optOffset = DnsTestMessages.queryQuestionEnd(query)
        writeU16(paddedQuery, optOffset + 9, paddingLength + 4)
        writeU16(paddedQuery, optionOffset, EDNS_PADDING_OPTION)
        writeU16(paddedQuery, optionOffset + 2, paddingLength)
        return paddedQuery
    }

    private fun assertIsValidUdpQuery(wire: ByteArray): ParsedDnsQuery =
        assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(wire)).query

    private fun assertIsValidTcpQuery(wire: ByteArray): ParsedDnsQuery =
        assertIs<DnsQueryParseResult.Valid>(
            DnsMessageValidator.parseQuery(wire, DnsTcpFrameCodec.MAX_DNS_MESSAGE_BYTES)
        ).query

    private fun newEd25519KeyPair(): KeyPair =
        KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private fun rawEd25519PublicKey(keyPair: KeyPair): ByteArray =
        keyPair.public.encoded.takeLast(ED25519_PUBLIC_KEY_BYTES).toByteArray()

    private fun keyTag(keyRdata: ByteArray): Int {
        var checksum = 0
        keyRdata.forEachIndexed { index, byte ->
            val byteShift = if (index % 2 == 0) 8 else 0
            checksum += (byte.toInt() and 0xFF) shl byteShift
        }
        checksum += (checksum ushr 16) and 0xFFFF
        return checksum and 0xFFFF
    }

    private fun resourceRecord(
        owner: ByteArray,
        type: Int,
        clazz: Int,
        ttl: Long,
        rdata: ByteArray
    ): ByteArray = owner + uint16(type) + uint16(clazz) + uint32(ttl) + uint16(rdata.size) + rdata

    private fun nextRecordOffset(message: ByteArray, recordOffset: Int): Int {
        val fieldsOffset = skipWireName(message, recordOffset)
        val rdataLength = readU16(message, fieldsOffset + 8)
        return fieldsOffset + DNS_RR_HEADER_BYTES + rdataLength
    }

    private fun skipWireName(message: ByteArray, nameOffset: Int): Int {
        var offset = nameOffset
        while (true) {
            val labelLength = message[offset].toInt() and 0xFF
            if (labelLength == 0) return offset + 1
            if (labelLength and 0xC0 == 0xC0) return offset + 2
            require(labelLength and 0xC0 == 0)
            offset += labelLength + 1
            require(offset <= message.size)
        }
    }

    private fun readU16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun writeU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun uint16(value: Int): ByteArray =
        byteArrayOf((value ushr 8).toByte(), value.toByte())

    private fun uint32(value: Long): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte()
    )

    private companion object {
        const val ADVERTISED_UDP_BYTES = 8_192
        const val DNS_RR_HEADER_BYTES = 10
        const val ED25519_DNSSEC_ALGORITHM = 15
        const val ED25519_PUBLIC_KEY_BYTES = 32
        const val ED25519_SIGNATURE_BYTES = 64
        const val EDNS_PADDING_OPTION = 12
        const val KEY_RR_TYPE = 25
        const val QUERY_NAME = "example.test"
        const val SIG_FIXED_RDATA_BYTES = 18
        const val SIG_RR_TYPE = 24
        const val SIGNER_NAME = "resolver.test"
        const val TEST_RESOLVER_ID = 7
    }
}
