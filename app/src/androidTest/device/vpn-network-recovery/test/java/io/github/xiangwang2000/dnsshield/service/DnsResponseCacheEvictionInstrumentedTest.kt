package io.github.xiangwang2000.dnsshield.service

import android.util.LruCache
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.blocking.CompiledBlocklistStatus
import io.github.xiangwang2000.dnsshield.blocking.DomainMatcher
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyAssembly
import java.io.ByteArrayOutputStream
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DnsResponseCacheEvictionInstrumentedTest {
    @Test
    fun actualServiceCacheWeightsLargeTcpQueriesAndKeepsSmallEntryLimit() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".d04test"))
        assertEquals(VpnLifecycleState.STOPPED, DnsVpnService.lifecycleStateFlow.value)
        val field = DnsVpnService::class.java.getDeclaredField("dnsCache").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val cache = field.get(null) as LruCache<DnsVpnService.Companion.DnsQueryKey, DnsResponseCacheEntry>
        val assembly = DomainPolicyAssembly(DomainMatcher { false }, CompiledBlocklistStatus.NotConfigured)
        val query = byteArrayOf(0,1,1,0,0,1,0,0,0,0,0,0,3,114,48,56,4,116,101,115,116,0,0,16,0,1)
        val parsed = (DnsMessageValidator.parseQuery(query) as DnsQueryParseResult.Valid).query

        fun queryWithPadding(targetSize: Int): ByteArray {
            require(targetSize in (query.size + 15)..DnsTcpFrameCodec.MAX_DNS_MESSAGE_BYTES)
            val padded = query.copyOf(targetSize)
            val optOffset = query.size
            val paddingSize = targetSize - optOffset - 15
            padded[11] = 1
            padded[optOffset + 2] = 41
            padded[optOffset + 3] = 4
            padded[optOffset + 4] = 0xD0.toByte()
            val optionLength = paddingSize + 4
            padded[optOffset + 9] = (optionLength ushr 8).toByte()
            padded[optOffset + 10] = optionLength.toByte()
            padded[optOffset + 12] = 12
            padded[optOffset + 13] = (paddingSize ushr 8).toByte()
            padded[optOffset + 14] = paddingSize.toByte()
            return padded
        }

        fun key(index: Int, queryBytes: ByteArray = query) =
            DnsVpnService.Companion.DnsQueryKey(queryBytes.copyOf(), index, 0L, assembly)
        fun entry(size: Int, queryForValidation: ParsedDnsQuery = parsed): DnsResponseCacheEntry {
            val response = query.copyOf().also { it[2]=0x81.toByte(); it[3]=0x80.toByte(); it[7]=1 }
            val rdataSize = size - response.size - 12
            val wire = ByteArrayOutputStream(size).apply {
                write(response)
                write(byteArrayOf(0xC0.toByte(),12,0,16,0,1,0,0,0,60,(rdataSize ushr 8).toByte(),rdataSize.toByte()))
                var remaining = rdataSize
                while (remaining > 0) {
                    val length = minOf(255, remaining-1)
                    write(length); write(ByteArray(length) { 65 }); remaining -= length+1
                }
            }.toByteArray()
            assertEquals(size, wire.size)
            return requireNotNull(DnsResponseCacheEntry.create(wire, queryForValidation) { 0L })
        }
        synchronized(cache) {
            val previous = cache.snapshot()
            try {
                cache.evictAll()
                assertEquals(2_048_000, cache.maxSize())
                val largeAnswer = entry(65_535)
                val answerWeight = largeAnswer.estimatedCacheWeightBytes(query.size)
                repeat(64) { cache.put(key(it), largeAnswer) }
                val answerFitting = cache.maxSize() / answerWeight
                assertEquals(answerFitting, cache.snapshot().size)
                assertEquals(answerFitting * answerWeight, cache.size())
                assertNull(cache.get(key(0)))
                assertNotNull(cache.get(key(63)))
                assertTrue(cache.size() <= cache.maxSize())

                cache.evictAll()
                val largeQuery = queryWithPadding(32 * 1024)
                val parsedLargeQuery = (DnsMessageValidator.parseQuery(
                    largeQuery,
                    DnsTcpFrameCodec.MAX_DNS_MESSAGE_BYTES
                ) as DnsQueryParseResult.Valid).query
                val smallResponseEntry = entry(query.size + 13, parsedLargeQuery)
                assertEquals(query.size + 13, smallResponseEntry.responseAtCurrentTime()?.size)
                val queryWeight = smallResponseEntry.estimatedCacheWeightBytes(largeQuery.size)
                assertTrue(queryWeight > smallResponseEntry.estimatedCacheWeightBytes)
                repeat(64) { cache.put(key(it, largeQuery), smallResponseEntry) }
                val queryFitting = cache.maxSize() / queryWeight
                assertEquals(queryFitting, cache.snapshot().size)
                assertEquals(queryFitting * queryWeight, cache.size())
                assertNull(cache.get(key(0, largeQuery)))
                assertNotNull(cache.get(key(63, largeQuery)))
                assertTrue(cache.size() <= cache.maxSize())

                cache.evictAll()
                val small = entry(query.size + 13)
                repeat(501) { cache.put(key(it), small) }
                assertEquals(500, cache.snapshot().size)
                assertNull(cache.get(key(0)))
                assertNotNull(cache.get(key(500)))
                assertTrue(cache.size() <= cache.maxSize())
            } finally {
                cache.evictAll()
                previous.forEach { (key,value) -> cache.put(key,value) }
            }
        }
    }
}
