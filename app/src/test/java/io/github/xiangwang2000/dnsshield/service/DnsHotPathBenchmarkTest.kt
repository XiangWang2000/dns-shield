package io.github.xiangwang2000.dnsshield.service

import io.github.xiangwang2000.dnsshield.blocking.BuiltInDomainMatcher
import io.github.xiangwang2000.dnsshield.blocking.CompiledBlocklistStatus
import io.github.xiangwang2000.dnsshield.blocking.DomainMatcher
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyAssembly
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Repeatable JVM microbenchmark for DNS query-key hashing and uncached built-in decisions.
 *
 * This intentionally has no pass/fail timing threshold: CI and developer machines have
 * different clocks. The stable comparison is the legacy and current implementation measured
 * back-to-back in the same warmed JVM. Gradle writes the printed result to the JUnit XML report.
 */
class DnsHotPathBenchmarkTest {
    @Test
    fun reportsMatcherAndQueryKeyCost() {
        val domains = buildDomains()
        val payloads = buildPayloads()
        val legacyMatcher = LegacyBuiltInDomainMatcher()
        val currentMatcher = BuiltInDomainMatcher()
        val policyAssembly = DomainPolicyAssembly(
            matcher = DomainMatcher { false },
            compiledBlocklistStatus = CompiledBlocklistStatus.NotConfigured
        )

        val legacyServiceMatcher = { domain: String ->
            legacyMatcher.shouldBlock(domain)
        }
        val currentServiceMatcher = { domain: String ->
            currentMatcher.shouldBlock(domain)
        }

        domains.forEach { domain ->
            assertEquals(legacyServiceMatcher(domain), currentServiceMatcher(domain), domain)
        }

        repeat(WARMUP_ROUNDS) {
            runMatcher(domains, legacyServiceMatcher)
            runMatcher(domains, currentServiceMatcher)
            runLegacyKeys(payloads, policyAssembly)
            runCurrentKeys(payloads, policyAssembly)
        }

        val (legacyMatcherNs, currentMatcherNs) = medianPairNanos(
            legacy = { runMatcher(domains, legacyServiceMatcher) },
            current = { runMatcher(domains, currentServiceMatcher) }
        )
        val (legacyKeyNs, currentKeyNs) = medianPairNanos(
            legacy = { runLegacyKeys(payloads, policyAssembly) },
            current = { runCurrentKeys(payloads, policyAssembly) }
        )

        val matcherOperations = domains.size.toLong() * MATCHER_REPETITIONS
        val keyOperations = payloads.size.toLong() * KEY_REPETITIONS
        val matcherLegacyNsPerOp = legacyMatcherNs.toDouble() / matcherOperations
        val matcherCurrentNsPerOp = currentMatcherNs.toDouble() / matcherOperations
        val keyLegacyNsPerOp = legacyKeyNs.toDouble() / keyOperations
        val keyCurrentNsPerOp = currentKeyNs.toDouble() / keyOperations

        println(
            "DNS_HOTPATH_BENCHMARK " +
                "built_in_matcher_legacy_ns_per_query=${format(matcherLegacyNsPerOp)} " +
                "built_in_matcher_current_ns_per_query=${format(matcherCurrentNsPerOp)} " +
                "built_in_matcher_speedup=${format(matcherLegacyNsPerOp / matcherCurrentNsPerOp)}x " +
                "query_key_hash_legacy_ns_per_query=${format(keyLegacyNsPerOp)} " +
                "query_key_hash_current_ns_per_query=${format(keyCurrentNsPerOp)} " +
                "query_key_hash_speedup=${format(keyLegacyNsPerOp / keyCurrentNsPerOp)}x"
        )

        assertTrue(benchmarkSink != 0L)
    }

    private fun runMatcher(domains: List<String>, shouldBlock: (String) -> Boolean) {
        var blocked = 0L
        repeat(MATCHER_REPETITIONS) {
            for (domain in domains) {
                if (shouldBlock(domain)) blocked++
            }
        }
        benchmarkSink = blocked
    }

    private fun runLegacyKeys(
        payloads: List<ByteArray>,
        policyAssembly: DomainPolicyAssembly
    ) {
        var hash = 0L
        repeat(KEY_REPETITIONS) {
            for (payload in payloads) {
                val key = LegacyDnsQueryKey(payload, 7, policyAssembly)
                repeat(HASH_LOOKUPS_PER_QUERY) {
                    hash += key.hashCode()
                }
            }
        }
        benchmarkSink = hash
    }

    private fun runCurrentKeys(
        payloads: List<ByteArray>,
        policyAssembly: DomainPolicyAssembly
    ) {
        var hash = 0L
        repeat(KEY_REPETITIONS) {
            for (payload in payloads) {
                val key = DnsVpnService.Companion.DnsQueryKey(payload, 7, policyAssembly)
                repeat(HASH_LOOKUPS_PER_QUERY) {
                    hash += key.hashCode()
                }
            }
        }
        benchmarkSink = hash
    }

    private fun medianPairNanos(legacy: () -> Unit, current: () -> Unit): Pair<Long, Long> {
        val legacySamples = LongArray(MEASURED_ROUNDS)
        val currentSamples = LongArray(MEASURED_ROUNDS)

        repeat(MEASURED_ROUNDS) { index ->
            if (index % 2 == 0) {
                legacySamples[index] = measureNanos(legacy)
                currentSamples[index] = measureNanos(current)
            } else {
                currentSamples[index] = measureNanos(current)
                legacySamples[index] = measureNanos(legacy)
            }
        }

        legacySamples.sort()
        currentSamples.sort()
        return legacySamples[legacySamples.size / 2] to currentSamples[currentSamples.size / 2]
    }

    private fun measureNanos(block: () -> Unit): Long {
        val startedAt = System.nanoTime()
        block()
        return System.nanoTime() - startedAt
    }

    private fun format(value: Double): String = String.format(Locale.ROOT, "%.2f", value)

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
            "doubleclick.net",
            "admob.com",
            "pagead2.googlesyndication.com",
            "googleads.g.doubleclick.net",
            "analytics.google.com",
            "crashlytics.com"
        )

        private val suffixBlocks = listOf(
            ".doubleclick.net",
            ".admob.com",
            ".analytics.google.com",
            ".adnxs.com",
            ".adcolony.com",
            ".adservice.google.com",
            ".scorecardresearch.com",
            ".hotjar.com",
            ".telemetry.mozilla.org",
            ".adjust.com",
            ".appsflyer.com"
        )

        private val containsBlocks = listOf(
            "adservice",
            "adsystem",
            "googleads",
            "pagead",
            "amazon-adsystem",
            "telemetry-",
            "analytics-"
        )

        private val exactBlockedLabels = setOf(
            "ads",
            "tracker",
            "telemetry",
            "analytics",
            "crashlytics"
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

    private companion object {
        const val DOMAIN_COUNT = 2_000
        const val PAYLOAD_COUNT = 512
        const val MATCHER_REPETITIONS = 200
        const val KEY_REPETITIONS = 800
        const val HASH_LOOKUPS_PER_QUERY = 4
        const val WARMUP_ROUNDS = 4
        const val MEASURED_ROUNDS = 7

        @Volatile
        var benchmarkSink = 0L
    }
}
