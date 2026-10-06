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
class R08CacheInstrumentedTest {
    @Test
    fun actualServiceCacheEvictsLargeAnswersByWeightAndKeepsSmallEntryLimit() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".d04test"))
        assertEquals(VpnLifecycleState.STOPPED, DnsVpnService.lifecycleStateFlow.value)
        val field = DnsVpnService::class.java.getDeclaredField("dnsCache").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val cache = field.get(null) as LruCache<DnsVpnService.Companion.DnsQueryKey, DnsResponseCacheEntry>
        val assembly = DomainPolicyAssembly(DomainMatcher { false }, CompiledBlocklistStatus.NotConfigured)
        val query = byteArrayOf(0,1,1,0,0,1,0,0,0,0,0,0,3,114,48,56,4,116,101,115,116,0,0,16,0,1)
        val parsed = (DnsMessageValidator.parseQuery(query) as DnsQueryParseResult.Valid).query
        fun key(index: Int) = DnsVpnService.Companion.DnsQueryKey(query.copyOf(), index, 0L, assembly)
        fun entry(size: Int): DnsResponseCacheEntry {
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
            return requireNotNull(DnsResponseCacheEntry.create(wire, parsed) { 0L })
        }
        synchronized(cache) {
            val previous = cache.snapshot()
            try {
                cache.evictAll()
                assertEquals(2_048_000, cache.maxSize())
                val large = entry(65_535)
                repeat(64) { cache.put(key(it), large) }
                val fitting = cache.maxSize() / large.estimatedCacheWeightBytes
                assertEquals(fitting, cache.snapshot().size)
                assertEquals(fitting * large.estimatedCacheWeightBytes, cache.size())
                assertNull(cache.get(key(0)))
                assertNotNull(cache.get(key(63)))
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
