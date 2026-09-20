package io.github.xiangwang2000.dnsshield.service

import java.util.Collections
import java.util.IdentityHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsResponseCacheTest {
    @Test
    fun ttlZeroIsNotCachedAndTtlOneExpiresAtOneSecond() {
        val queryBytes = DnsTestMessages.query(transactionId = 0x2011)
        val query = parsedQuery(queryBytes)
        val zeroTtl = positiveResponse(queryBytes, ttl = 0)
        assertNull(DnsResponseCacheEntry.create(zeroTtl, query) { 0L })

        var monotonicMillis = 10_000L
        val oneSecond = positiveResponse(queryBytes, ttl = 1)
        val entry = assertNotNull(DnsResponseCacheEntry.create(oneSecond, query) { monotonicMillis })
        assertEquals(1L, onlyRecord(entry.responseAtCurrentTime()).ttl)

        monotonicMillis += 1_000L
        assertNull(entry.responseAtCurrentTime())
    }

    @Test
    fun decrementsTtlFourAndExpiresAtTheOriginalTtl() {
        val queryBytes = DnsTestMessages.query(transactionId = 0x2012)
        val query = parsedQuery(queryBytes)
        var monotonicMillis = 50_000L
        val response = positiveResponse(queryBytes, ttl = 4)
        val entry = assertNotNull(DnsResponseCacheEntry.create(response, query) { monotonicMillis })

        monotonicMillis += 2_000L
        assertEquals(2L, onlyRecord(entry.responseAtCurrentTime()).ttl)
        monotonicMillis += 2_000L
        assertNull(entry.responseAtCurrentTime())
    }

    @Test
    fun expiresTtlThreeHundredAtItsBoundaryAndCapsLongerResidency() {
        val queryBytes = DnsTestMessages.query(transactionId = 0x2013)
        val query = parsedQuery(queryBytes)
        var monotonicMillis = 100L
        val threeHundred = positiveResponse(queryBytes, ttl = 300)
        val entry = assertNotNull(DnsResponseCacheEntry.create(threeHundred, query) { monotonicMillis })

        monotonicMillis += 299_000L
        assertEquals(1L, onlyRecord(entry.responseAtCurrentTime()).ttl)
        monotonicMillis += 1_000L
        assertNull(entry.responseAtCurrentTime())

        monotonicMillis = 5_000L
        val longTtl = positiveResponse(queryBytes, ttl = 600)
        val cappedEntry = assertNotNull(DnsResponseCacheEntry.create(longTtl, query) { monotonicMillis })
        monotonicMillis += 300_000L
        assertNull(cappedEntry.responseAtCurrentTime())
    }

    @Test
    fun decrementsEveryPositiveSectionTtlAndPreservesOptFields() {
        val queryBytes = DnsTestMessages.query(edns = true, transactionId = 0x2014)
        val query = parsedQuery(queryBytes)
        val optFlags = 0x0000_8000L
        val response = DnsTestMessages.responseWithRecords(
            queryBytes,
            answers = listOf(aRecord(ttl = 20)),
            authorities = listOf(
                DnsTestResourceRecord(
                    type = 2,
                    ttl = 30,
                    data = DnsTestMessages.encodedName("ns.example.com"),
                    ownerName = "example.com"
                )
            ),
            additionals = listOf(
                DnsTestResourceRecord(
                    type = 1,
                    ttl = 40,
                    data = byteArrayOf(192.toByte(), 0, 2, 53),
                    ownerName = "ns.example.com"
                ),
                DnsTestResourceRecord(
                    type = 41,
                    ttl = optFlags,
                    data = byteArrayOf(),
                    clazz = 1232,
                    ownerName = ""
                )
            )
        )
        var monotonicMillis = 2_000L
        val entry = assertNotNull(DnsResponseCacheEntry.create(response, query) { monotonicMillis })

        monotonicMillis += 5_000L
        val cached = assertNotNull(entry.responseAtCurrentTime())
        val records = DnsTestMessages.records(cached)
        assertEquals(listOf(0, 1, 2, 2), records.map { it.section })
        assertEquals(listOf(15L, 25L, 35L, optFlags), records.map { it.ttl })
    }

    @Test
    fun decrementsEachTtlInAMixedTtlCnameChain() {
        val queryBytes = DnsTestMessages.query(transactionId = 0x2015)
        val query = parsedQuery(queryBytes)
        val response = DnsTestMessages.responseWithRecords(
            queryBytes,
            answers = listOf(
                DnsTestResourceRecord(
                    type = 5,
                    ttl = 4,
                    data = DnsTestMessages.encodedName("alias.example.com"),
                    ownerName = "example.com"
                ),
                DnsTestResourceRecord(
                    type = 5,
                    ttl = 3,
                    data = DnsTestMessages.encodedName("final.example.com"),
                    ownerName = "alias.example.com"
                ),
                DnsTestResourceRecord(
                    type = 1,
                    ttl = 8,
                    data = byteArrayOf(192.toByte(), 0, 2, 80),
                    ownerName = "final.example.com"
                )
            )
        )
        var monotonicMillis = 12_000L
        val entry = assertNotNull(DnsResponseCacheEntry.create(response, query) { monotonicMillis })

        monotonicMillis += 1_000L
        assertEquals(listOf(3L, 2L, 7L), DnsTestMessages.records(assertNotNull(entry.responseAtCurrentTime())).map { it.ttl })
    }

    @Test
    fun negativeNxdomainAndNodataUseTheMinimumOfSoaTtlAndMinimum() {
        val queryBytes = DnsTestMessages.query(transactionId = 0x2016)
        val query = parsedQuery(queryBytes)
        val soa = soaRecord(ttl = 60, minimum = 5)
        var monotonicMillis = 1_000L

        val nxdomain = DnsTestMessages.responseWithRecords(
            queryBytes,
            authorities = listOf(soa),
            flags = 0x8183
        )
        val nxEntry = assertNotNull(DnsResponseCacheEntry.create(nxdomain, query) { monotonicMillis })
        assertEquals(5L, onlyRecord(assertNotNull(nxEntry.responseAtCurrentTime())).ttl)
        monotonicMillis += 2_000L
        assertEquals(3L, onlyRecord(assertNotNull(nxEntry.responseAtCurrentTime())).ttl)

        monotonicMillis = 10_000L
        val nodata = DnsTestMessages.responseWithRecords(
            queryBytes,
            authorities = listOf(soaRecord(ttl = 3, minimum = 5))
        )
        val nodataEntry = assertNotNull(DnsResponseCacheEntry.create(nodata, query) { monotonicMillis })
        assertEquals(3L, onlyRecord(assertNotNull(nodataEntry.responseAtCurrentTime())).ttl)
    }

    @Test
    fun rejectsNegativeResponsesWithoutSoa() {
        val queryBytes = DnsTestMessages.query(transactionId = 0x2017)
        val query = parsedQuery(queryBytes)
        val nxDomainWithoutSoa = DnsTestMessages.responseWithRecords(queryBytes, flags = 0x8183)
        val nodataWithoutSoa = DnsTestMessages.responseWithRecords(queryBytes)

        assertNull(DnsResponseCacheEntry.create(nxDomainWithoutSoa, query) { 0L })
        assertNull(DnsResponseCacheEntry.create(nodataWithoutSoa, query) { 0L })
    }

    @Test
    fun cnameOnlyAnswerWithSoaUsesNegativeTtlForTheTargetNodata() {
        val queryBytes = DnsTestMessages.query(transactionId = 0x201A)
        val query = parsedQuery(queryBytes)
        val response = DnsTestMessages.responseWithRecords(
            queryBytes,
            answers = listOf(
                DnsTestResourceRecord(
                    type = 5,
                    ttl = 60,
                    data = DnsTestMessages.encodedName("missing.example.com")
                )
            ),
            authorities = listOf(soaRecord(ttl = 3_600, minimum = 5))
        )
        var monotonicMillis = 1_000L
        val entry = assertNotNull(DnsResponseCacheEntry.create(response, query) { monotonicMillis })

        monotonicMillis += 4_000L
        assertEquals(listOf(56L, 1L), DnsTestMessages.records(assertNotNull(entry.responseAtCurrentTime())).map { it.ttl })
        monotonicMillis += 1_000L
        assertNull(entry.responseAtCurrentTime())
    }

    @Test
    fun rejectsServfailRefusedTruncatedAndMalformedRecords() {
        val queryBytes = DnsTestMessages.query(transactionId = 0x2018)
        val query = parsedQuery(queryBytes)
        val servfail = DnsTestMessages.responseWithRecords(queryBytes, flags = 0x8182)
        val refused = DnsTestMessages.responseWithRecords(queryBytes, flags = 0x8185)
        val truncated = DnsTestMessages.responseWithRecords(queryBytes, flags = 0x8380)
        val malformedA = DnsTestMessages.responseWithRecords(
            queryBytes,
            answers = listOf(DnsTestResourceRecord(type = 1, ttl = 30, data = byteArrayOf(192.toByte(), 0, 2)))
        )
        val malformedSoa = DnsTestMessages.responseWithRecords(
            queryBytes,
            flags = 0x8183,
            authorities = listOf(DnsTestResourceRecord(type = 6, ttl = 30, data = byteArrayOf(1)))
        )

        listOf(servfail, refused, truncated, malformedA, malformedSoa).forEach { response ->
            assertNull(DnsResponseCacheEntry.create(response, query) { 0L })
        }
        assertFalse(DnsMessageValidator.isValidResponse(malformedA, query))
        assertFalse(DnsMessageValidator.isValidResponse(malformedSoa, query))
    }

    @Test
    fun usesInjectedMonotonicTimeRegardlessOfSimulatedWallClockJumps() {
        val queryBytes = DnsTestMessages.query(transactionId = 0x2019)
        val query = parsedQuery(queryBytes)
        var monotonicMillis = 20_000L
        var simulatedWallClockMillis = 1_700_000_000_000L
        val creationWallClockMillis = simulatedWallClockMillis
        val response = positiveResponse(queryBytes, ttl = 4)
        val entry = assertNotNull(DnsResponseCacheEntry.create(response, query) { monotonicMillis })

        simulatedWallClockMillis = 1_000L
        assertNotEquals(creationWallClockMillis, simulatedWallClockMillis)
        assertEquals(4L, onlyRecord(assertNotNull(entry.responseAtCurrentTime())).ttl)

        monotonicMillis += 2_000L
        simulatedWallClockMillis = Long.MAX_VALUE
        assertEquals(Long.MAX_VALUE, simulatedWallClockMillis)
        assertEquals(2L, onlyRecord(assertNotNull(entry.responseAtCurrentTime())).ttl)
    }

    @Test
    fun concurrentReadsReturnIndependentCopiesWithStableTransactionIds() {
        val queryBytes = DnsTestMessages.query(transactionId = 0x4A21)
        val query = parsedQuery(queryBytes)
        val response = positiveResponse(queryBytes, ttl = 60)
        val expected = response.copyOf()
        val entry = assertNotNull(DnsResponseCacheEntry.create(response, query) { 40_000L })
        response.fill(0x55)

        val readerCount = 32
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(8)
        try {
            val futures = (0 until readerCount).map {
                executor.submit<ByteArray?> {
                    start.await()
                    entry.responseAtCurrentTime()
                }
            }
            start.countDown()
            val results = futures.map { assertNotNull(it.get(5, TimeUnit.SECONDS)) }
            val identities = Collections.newSetFromMap(IdentityHashMap<ByteArray, Boolean>())
            identities.addAll(results)

            assertEquals(readerCount, identities.size)
            assertTrue(results.all { transactionId(it) == 0x4A21 })
            assertTrue(results.all { it.contentEquals(expected) })

            results.first()[0] = 0
            assertContentEquals(expected, results[1])
            assertContentEquals(expected, assertNotNull(entry.responseAtCurrentTime()))
        } finally {
            executor.shutdownNow()
        }
    }

    private fun parsedQuery(message: ByteArray): ParsedDnsQuery =
        assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(message)).query

    private fun positiveResponse(query: ByteArray, ttl: Long): ByteArray =
        DnsTestMessages.responseWithRecords(query, answers = listOf(aRecord(ttl)))

    private fun aRecord(ttl: Long): DnsTestResourceRecord =
        DnsTestResourceRecord(type = 1, ttl = ttl, data = byteArrayOf(192.toByte(), 0, 2, 1))

    private fun soaRecord(ttl: Long, minimum: Long): DnsTestResourceRecord {
        val data = DnsTestMessages.encodedName("ns.example.com") +
            DnsTestMessages.encodedName("hostmaster.example.com") +
            uint32(1) + uint32(3_600) + uint32(600) + uint32(86_400) + uint32(minimum)
        return DnsTestResourceRecord(type = 6, ttl = ttl, data = data, ownerName = "example.com")
    }

    private fun uint32(value: Long): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte()
    )

    private fun onlyRecord(message: ByteArray?): DnsTestRecordView {
        val records = DnsTestMessages.records(assertNotNull(message))
        assertEquals(1, records.size)
        return records.single()
    }

    private fun transactionId(message: ByteArray): Int =
        ((message[0].toInt() and 0xFF) shl 8) or (message[1].toInt() and 0xFF)
}
