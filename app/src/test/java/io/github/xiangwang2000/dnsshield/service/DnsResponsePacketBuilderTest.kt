package io.github.xiangwang2000.dnsshield.service

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

class DnsResponsePacketBuilderTest {
    @Test
    fun stampsTransactionIdDuringPacketCopyWithoutMutatingCachedResponse() {
        val sourceIp = byteArrayOf(10, 0, 0, 1)
        val destinationIp = byteArrayOf(10, 0, 0, 2)
        val transactionId = byteArrayOf(0x12, 0x34)

        listOf(0, 1, 2, 64, 512, 1500).forEach { size ->
            val cachedResponse = ByteArray(size) { it.toByte() }
            val original = cachedResponse.copyOf()
            val legacyResponse = cachedResponse.copyOf().also {
                if (it.size >= 2) {
                    it[0] = transactionId[0]
                    it[1] = transactionId[1]
                }
            }
            val expected = DnsResponsePacketBuilder.build(
                sourceIp,
                destinationIp,
                53,
                53000,
                legacyResponse
            )
            val actual = DnsResponsePacketBuilder.build(
                sourceIp,
                destinationIp,
                53,
                53000,
                cachedResponse,
                transactionId
            )

            assertContentEquals(expected, actual, "payload size $size")
            assertContentEquals(original, cachedResponse, "cached response size $size")
        }
    }

    @Test
    fun concurrentCacheHitsStampEachClientIdWithoutMutatingTheSharedResponse() {
        val originalQuery = DnsTestMessages.query(transactionId = 0x1234)
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(originalQuery)).query
        val originalResponse = DnsTestMessages.responseWithRecords(
            originalQuery,
            answers = listOf(DnsTestResourceRecord(type = 1, ttl = 60, data = byteArrayOf(192.toByte(), 0, 2, 1)))
        )
        val originalResponseCopy = originalResponse.copyOf()
        val entry = assertNotNull(DnsResponseCacheEntry.create(originalResponse, query) { 10_000L })
        val expectedCacheHit = assertNotNull(entry.responseAtCurrentTime())
        val sourceIp = byteArrayOf(10, 0, 0, 1)
        val destinationIp = byteArrayOf(10, 0, 0, 2)
        val clientQueries = (0 until 32).map { index ->
            DnsTestMessages.query(transactionId = 0x4000 + index)
        }
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(8)

        try {
            val futures = clientQueries.mapIndexed { index, clientQuery ->
                executor.submit<ByteArray> {
                    start.await()
                    val cacheHit = assertNotNull(entry.responseAtCurrentTime())
                    DnsResponsePacketBuilder.build(
                        sourceIp,
                        destinationIp,
                        53,
                        53000 + index,
                        cacheHit,
                        clientQuery
                    )
                }
            }
            start.countDown()
            val packets = futures.map { it.get(5, TimeUnit.SECONDS) }

            packets.forEachIndexed { index, packet ->
                val expectedId = 0x4000 + index
                val actualId = ((packet[28].toInt() and 0xFF) shl 8) or (packet[29].toInt() and 0xFF)
                assertEquals(expectedId, actualId)
            }
            assertContentEquals(originalResponseCopy, originalResponse)
            assertContentEquals(expectedCacheHit, assertNotNull(entry.responseAtCurrentTime()))
        } finally {
            executor.shutdownNow()
        }
    }
}
