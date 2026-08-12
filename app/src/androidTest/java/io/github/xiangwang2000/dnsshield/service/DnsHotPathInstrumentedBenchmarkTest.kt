package io.github.xiangwang2000.dnsshield.service

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.blocking.BuiltInDomainMatcher
import io.github.xiangwang2000.dnsshield.blocking.CompiledBlocklistStatus
import io.github.xiangwang2000.dnsshield.blocking.DomainMatcher
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyAssembly
import java.io.File
import kotlin.math.ceil
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Paired on-device benchmark for the two CPU changes in the DNS request hot path. */
@RunWith(AndroidJUnit4::class)
class DnsHotPathInstrumentedBenchmarkTest {
    @Test
    fun benchmarkLegacyAndCurrentHotPaths() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext
        val domains = buildDomains()
        val payloads = buildPayloads()
        val legacyMatcher = LegacyBuiltInDomainMatcher()
        val currentMatcher = BuiltInDomainMatcher()
        val policyAssembly = DomainPolicyAssembly(
            matcher = DomainMatcher { false },
            compiledBlocklistStatus = CompiledBlocklistStatus.NotConfigured
        )

        domains.forEach { domain ->
            assertEquals(domain, legacyMatcher.shouldBlock(domain), currentMatcher.shouldBlock(domain))
        }

        repeat(WARMUP_BATCHES) {
            runMatcherBatch(domains, legacyMatcher::shouldBlock)
            runMatcherBatch(domains, currentMatcher::shouldBlock)
            runLegacyKeyBatch(payloads, policyAssembly)
            runCurrentKeyBatch(payloads, policyAssembly)
        }

        val matcherSamples = pairedSamples(
            legacy = { runMatcherBatch(domains, legacyMatcher::shouldBlock) },
            current = { runMatcherBatch(domains, currentMatcher::shouldBlock) }
        )
        val keySamples = pairedSamples(
            legacy = { runLegacyKeyBatch(payloads, policyAssembly) },
            current = { runCurrentKeyBatch(payloads, policyAssembly) }
        )

        val matcherQueriesPerBatch = domains.size.toLong() * MATCHER_REPETITIONS
        val keyQueriesPerBatch = payloads.size.toLong() * KEY_REPETITIONS
        val report = Report(
            model = android.os.Build.MODEL,
            androidRelease = android.os.Build.VERSION.RELEASE,
            apiLevel = android.os.Build.VERSION.SDK_INT,
            abi = android.os.Build.SUPPORTED_ABIS.first(),
            sampleBatches = SAMPLE_BATCHES,
            builtInMatcherQueriesPerBatch = matcherQueriesPerBatch,
            builtInMatcherLegacyMedianNanos = median(matcherSamples.first) / matcherQueriesPerBatch,
            builtInMatcherCurrentMedianNanos = median(matcherSamples.second) / matcherQueriesPerBatch,
            builtInMatcherLegacyP95Nanos = percentile(matcherSamples.first, 0.95) / matcherQueriesPerBatch,
            builtInMatcherCurrentP95Nanos = percentile(matcherSamples.second, 0.95) / matcherQueriesPerBatch,
            queryKeyHashQueriesPerBatch = keyQueriesPerBatch,
            hashLookupsPerQuery = HASH_LOOKUPS_PER_QUERY,
            queryKeyHashLegacyMedianNanos = median(keySamples.first) / keyQueriesPerBatch,
            queryKeyHashCurrentMedianNanos = median(keySamples.second) / keyQueriesPerBatch,
            queryKeyHashLegacyP95Nanos = percentile(keySamples.first, 0.95) / keyQueriesPerBatch,
            queryKeyHashCurrentP95Nanos = percentile(keySamples.second, 0.95) / keyQueriesPerBatch
        )

        val reportDirectory = checkNotNull(targetContext.getExternalFilesDir(null))
        val reportFile = File(reportDirectory, REPORT_FILE_NAME)
        reportFile.writeText(report.toJson(), Charsets.UTF_8)
        println("DNS_SHIELD_DNS_HOTPATH_ANDROID_REPORT=${reportFile.absolutePath}")
        println(report.toJson())

        assertTrue(benchmarkSink != 0L)
    }

    private fun pairedSamples(legacy: () -> Unit, current: () -> Unit): Pair<LongArray, LongArray> {
        val legacySamples = LongArray(SAMPLE_BATCHES)
        val currentSamples = LongArray(SAMPLE_BATCHES)
        repeat(SAMPLE_BATCHES) { index ->
            if (index % 2 == 0) {
                legacySamples[index] = measureNanos(legacy)
                currentSamples[index] = measureNanos(current)
            } else {
                currentSamples[index] = measureNanos(current)
                legacySamples[index] = measureNanos(legacy)
            }
        }
        return legacySamples to currentSamples
    }

    private fun runMatcherBatch(domains: List<String>, shouldBlock: (String) -> Boolean) {
        var blocked = 0L
        repeat(MATCHER_REPETITIONS) {
            for (domain in domains) {
                if (shouldBlock(domain)) blocked++
            }
        }
        benchmarkSink = blocked
    }

    private fun runLegacyKeyBatch(payloads: List<ByteArray>, policyAssembly: DomainPolicyAssembly) {
        var hash = 0L
        repeat(KEY_REPETITIONS) {
            for (payload in payloads) {
                val key = LegacyDnsQueryKey(payload, 7, policyAssembly)
                repeat(HASH_LOOKUPS_PER_QUERY) { hash += key.hashCode() }
            }
        }
        benchmarkSink = hash
    }

    private fun runCurrentKeyBatch(payloads: List<ByteArray>, policyAssembly: DomainPolicyAssembly) {
        var hash = 0L
        repeat(KEY_REPETITIONS) {
            for (payload in payloads) {
                val key = DnsVpnService.Companion.DnsQueryKey(payload, 7, policyAssembly)
                repeat(HASH_LOOKUPS_PER_QUERY) { hash += key.hashCode() }
            }
        }
        benchmarkSink = hash
    }

    private fun buildDomains(): List<String> = List(DOMAIN_COUNT) { index ->
        when (index % 5) {
            0 -> "cdn-$index.example.com"
            1 -> "api.ads.customer$index.com"
            2 -> "node$index.appsflyer.com"
            3 -> "telemetry-edge$index.example.net"
            else -> "SEARCH-$index.EXAMPLE.ORG"
        }
    }

    private fun buildPayloads(): List<ByteArray> = List(PAYLOAD_COUNT) { index ->
        ByteArray(64) { byteIndex ->
            when (byteIndex) {
                0 -> (index ushr 8).toByte()
                1 -> index.toByte()
                else -> (index * 31 + byteIndex * 17).toByte()
            }
        }
    }

    private fun median(values: LongArray): Long = percentile(values, 0.5)

    private fun percentile(values: LongArray, percentile: Double): Long {
        val sorted = values.sortedArray()
        val index = (ceil(percentile * sorted.size).toInt() - 1).coerceIn(sorted.indices)
        return sorted[index]
    }

    private class LegacyDnsQueryKey(
        private val bytes: ByteArray,
        private val resolverGeneration: Int,
        private val policyAssembly: DomainPolicyAssembly
    ) {
        override fun hashCode(): Int {
            var result = 31 * resolverGeneration + System.identityHashCode(policyAssembly)
            for (index in 2 until bytes.size) {
                result = 31 * result + bytes[index]
            }
            return result
        }
    }

    private class LegacyBuiltInDomainMatcher {
        private val exactBlocks = setOf(
            "doubleclick.net", "admob.com", "pagead2.googlesyndication.com",
            "googleads.g.doubleclick.net", "analytics.google.com", "crashlytics.com"
        )
        private val suffixBlocks = listOf(
            ".doubleclick.net", ".admob.com", ".analytics.google.com", ".adnxs.com",
            ".adcolony.com", ".adservice.google.com", ".scorecardresearch.com", ".hotjar.com",
            ".telemetry.mozilla.org", ".adjust.com", ".appsflyer.com"
        )
        private val containsBlocks = listOf(
            "adservice", "adsystem", "googleads", "pagead", "amazon-adsystem",
            "telemetry-", "analytics-"
        )
        private val exactBlockedLabels = setOf(
            "ads", "tracker", "telemetry", "analytics", "crashlytics"
        )

        fun shouldBlock(domain: String): Boolean {
            val normalized = domain.lowercase().trim()
            if (normalized.isEmpty() || normalized == "unknown") return false
            if (normalized in exactBlocks) return true
            if (suffixBlocks.any(normalized::endsWith)) return true
            if (containsBlocks.any(normalized::contains)) return true
            return normalized.split('.').any(exactBlockedLabels::contains)
        }
    }

    private data class Report(
        val model: String,
        val androidRelease: String,
        val apiLevel: Int,
        val abi: String,
        val sampleBatches: Int,
        val builtInMatcherQueriesPerBatch: Long,
        val builtInMatcherLegacyMedianNanos: Long,
        val builtInMatcherCurrentMedianNanos: Long,
        val builtInMatcherLegacyP95Nanos: Long,
        val builtInMatcherCurrentP95Nanos: Long,
        val queryKeyHashQueriesPerBatch: Long,
        val hashLookupsPerQuery: Int,
        val queryKeyHashLegacyMedianNanos: Long,
        val queryKeyHashCurrentMedianNanos: Long,
        val queryKeyHashLegacyP95Nanos: Long,
        val queryKeyHashCurrentP95Nanos: Long
    ) {
        fun toJson(): String = """
            {
              "model": "$model",
              "android_release": "$androidRelease",
              "api_level": $apiLevel,
              "abi": "$abi",
              "sample_batches": $sampleBatches,
              "built_in_matcher_queries_per_batch": $builtInMatcherQueriesPerBatch,
              "built_in_matcher_legacy_median_nanos": $builtInMatcherLegacyMedianNanos,
              "built_in_matcher_current_median_nanos": $builtInMatcherCurrentMedianNanos,
              "built_in_matcher_legacy_p95_nanos": $builtInMatcherLegacyP95Nanos,
              "built_in_matcher_current_p95_nanos": $builtInMatcherCurrentP95Nanos,
              "query_key_hash_queries_per_batch": $queryKeyHashQueriesPerBatch,
              "hash_lookups_per_query": $hashLookupsPerQuery,
              "query_key_hash_legacy_median_nanos": $queryKeyHashLegacyMedianNanos,
              "query_key_hash_current_median_nanos": $queryKeyHashCurrentMedianNanos,
              "query_key_hash_legacy_p95_nanos": $queryKeyHashLegacyP95Nanos,
              "query_key_hash_current_p95_nanos": $queryKeyHashCurrentP95Nanos
            }
        """.trimIndent() + "\n"
    }

    private companion object {
        const val REPORT_FILE_NAME = "dns-hotpath.android-benchmark.json"
        const val DOMAIN_COUNT = 2_000
        const val PAYLOAD_COUNT = 512
        const val MATCHER_REPETITIONS = 100
        const val KEY_REPETITIONS = 400
        const val HASH_LOOKUPS_PER_QUERY = 4
        const val WARMUP_BATCHES = 4
        const val SAMPLE_BATCHES = 15

        @Volatile
        var benchmarkSink = 0L
    }
}

private inline fun measureNanos(block: () -> Unit): Long {
    val started = System.nanoTime()
    block()
    return System.nanoTime() - started
}
