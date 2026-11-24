package io.github.xiangwang2000.dnsshield.service

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Repeatable JVM microbenchmark for per-query log formatting helpers.
 *
 * There is no pass/fail timing threshold: CI and developer machines have different clocks.
 * The stable comparison is the legacy and current implementation measured back-to-back in the
 * same warmed JVM. Gradle writes the printed result to the JUnit XML report.
 */
class DnsLogFormattingBenchmarkTest {
    @Test
    fun timestampReflectsDefaultTimeZoneChangesOnTheSameThread() {
        val originalZone = TimeZone.getDefault()
        try {
            TimeZone.setDefault(TimeZone.getTimeZone("UTC"))
            assertEquals(legacyTimestamp(0L), DnsLogFormatting.timestamp(0L))

            TimeZone.setDefault(TimeZone.getTimeZone("GMT+08:00"))
            assertEquals(legacyTimestamp(0L), DnsLogFormatting.timestamp(0L))
        } finally {
            TimeZone.setDefault(originalZone)
        }
    }

    @Test
    fun timestampPreservesLocaleTimeZoneOverrideOnTheSameThread() {
        val originalLocale = Locale.getDefault()
        val originalDisplayLocale = Locale.getDefault(Locale.Category.DISPLAY)
        val originalFormatLocale = Locale.getDefault(Locale.Category.FORMAT)
        val originalZone = TimeZone.getDefault()
        try {
            TimeZone.setDefault(TimeZone.getTimeZone("UTC"))
            Locale.setDefault(Locale.US)
            assertEquals(legacyTimestamp(0L), DnsLogFormatting.timestamp(0L))

            Locale.setDefault(Locale.forLanguageTag("en-US-u-tz-uslax"))
            assertEquals(legacyTimestamp(0L), DnsLogFormatting.timestamp(0L))
        } finally {
            Locale.setDefault(originalLocale)
            Locale.setDefault(Locale.Category.DISPLAY, originalDisplayLocale)
            Locale.setDefault(Locale.Category.FORMAT, originalFormatLocale)
            TimeZone.setDefault(originalZone)
        }
    }

    @Test
    fun reportsTransactionIdAndTimestampCost() {
        val payloads = buildPayloads()
        val domains = buildDomains()
        val fixedNowMillis = 1_736_000_000_000L

        payloads.forEach { payload ->
            assertEquals(legacyTransactionId(payload), DnsLogFormatting.transactionId(payload))
        }
        assertEquals(legacyTimestamp(fixedNowMillis), DnsLogFormatting.timestamp(fixedNowMillis))

        repeat(WARMUP_ROUNDS) {
            runLegacyTransactionIds(payloads)
            runCurrentTransactionIds(payloads)
            runLegacyTimestamps(fixedNowMillis)
            runCurrentTimestamps(fixedNowMillis)
            runLegacySavedBytes(domains)
        }

        val (legacyTxIdNs, currentTxIdNs) = medianPairNanos(
            legacy = { runLegacyTransactionIds(payloads) },
            current = { runCurrentTransactionIds(payloads) }
        )
        val (legacyTimestampNs, currentTimestampNs) = medianPairNanos(
            legacy = { runLegacyTimestamps(fixedNowMillis) },
            current = { runCurrentTimestamps(fixedNowMillis) }
        )
        val legacySavedBytesNs = medianNanos { runLegacySavedBytes(domains) }

        val operations = payloads.size.toLong() * REPETITIONS
        val legacyTxIdPerOp = legacyTxIdNs.toDouble() / operations
        val currentTxIdPerOp = currentTxIdNs.toDouble() / operations
        val legacyTimestampPerOp = legacyTimestampNs.toDouble() / REPETITIONS
        val currentTimestampPerOp = currentTimestampNs.toDouble() / REPETITIONS
        val legacySavedBytesPerOp = legacySavedBytesNs.toDouble() / operations

        println(
            "DNS_LOG_FORMAT_BENCHMARK " +
                "transaction_id_legacy_ns_per_query=${format(legacyTxIdPerOp)} " +
                "transaction_id_current_ns_per_query=${format(currentTxIdPerOp)} " +
                "transaction_id_speedup=${format(legacyTxIdPerOp / currentTxIdPerOp)}x " +
                "timestamp_legacy_ns_per_query=${format(legacyTimestampPerOp)} " +
                "timestamp_current_ns_per_query=${format(currentTimestampPerOp)} " +
                "timestamp_speedup=${format(legacyTimestampPerOp / currentTimestampPerOp)}x " +
                "estimate_saved_bytes_legacy_ns_per_blocked_query=${format(legacySavedBytesPerOp)} " +
                "estimate_saved_bytes_current_ns_per_blocked_query=0.00 (removed)"
        )

        assertTrue(benchmarkSink != 0L)
    }

    private fun runLegacyTransactionIds(payloads: List<ByteArray>) {
        var sum = 0
        repeat(REPETITIONS) {
            for (payload in payloads) {
                sum += legacyTransactionId(payload).length
            }
        }
        benchmarkSink = sum.toLong()
    }

    private fun runCurrentTransactionIds(payloads: List<ByteArray>) {
        var sum = 0
        repeat(REPETITIONS) {
            for (payload in payloads) {
                sum += DnsLogFormatting.transactionId(payload).length
            }
        }
        benchmarkSink = sum.toLong()
    }

    private fun runLegacyTimestamps(nowMillis: Long) {
        var sum = 0
        repeat(REPETITIONS) {
            sum += legacyTimestamp(nowMillis).length
        }
        benchmarkSink = sum.toLong()
    }

    private fun runCurrentTimestamps(nowMillis: Long) {
        var sum = 0
        repeat(REPETITIONS) {
            sum += DnsLogFormatting.timestamp(nowMillis).length
        }
        benchmarkSink = sum.toLong()
    }

    private fun runLegacySavedBytes(domains: List<String>) {
        var sum = 0L
        repeat(REPETITIONS) {
            for (domain in domains) {
                sum += legacyEstimateSavedBytes(domain)
            }
        }
        benchmarkSink = sum
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

    private fun medianNanos(block: () -> Unit): Long {
        val samples = LongArray(MEASURED_ROUNDS) { measureNanos(block) }
        samples.sort()
        return samples[samples.size / 2]
    }

    private fun measureNanos(block: () -> Unit): Long {
        val startedAt = System.nanoTime()
        block()
        return System.nanoTime() - startedAt
    }

    private fun format(value: Double): String = String.format(Locale.ROOT, "%.2f", value)

    private fun buildPayloads(): List<ByteArray> = List(PAYLOAD_COUNT) { index ->
        ByteArray(64) { byteIndex ->
            when (byteIndex) {
                0 -> (index ushr 8).toByte()
                1 -> index.toByte()
                else -> (index * 31 + byteIndex * 17).toByte()
            }
        }
    }

    private fun buildDomains(): List<String> = List(PAYLOAD_COUNT) { index ->
        when (index % 5) {
            0 -> "video-ads$index.doubleclick.net"
            1 -> "api.analytics.customer$index.com"
            2 -> "node$index.appsflyer.com"
            3 -> "telemetry-edge$index.example.net"
            else -> "cdn-$index.example.org"
        }
    }

    private fun legacyTransactionId(dnsPayload: ByteArray): String =
        if (dnsPayload.size >= 2) {
            String.format("0x%02X%02X", dnsPayload[0], dnsPayload[1])
        } else {
            "Unknown"
        }

    private fun legacyTimestamp(nowMillis: Long): String =
        SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(nowMillis))

    private fun legacyEstimateSavedBytes(domain: String): Long {
        val d = domain.lowercase()
        return when {
            d.contains("video") || d.contains("vast") || d.contains("vpaid") -> 2_000 * 1024L
            d.contains("doubleclick") || d.contains("googlesyndication") ||
                d.contains("googleads") || d.contains("admob") || d.contains("adservice") ||
                d.contains("adsystem") || d.contains("amazon-adsystem") -> 500 * 1024L
            d.contains("analytics") || d.contains("measurement") ||
                d.contains("app-measurement") -> 30 * 1024L
            d.contains("crashlytics") || d.contains("crash") -> 15 * 1024L
            d.contains("telemetry") -> 40 * 1024L
            d.contains("tracker") || d.contains("tracking") ||
                d.contains("adjust") || d.contains("appsflyer") -> 80 * 1024L
            else -> 100 * 1024L
        }
    }

    private companion object {
        const val PAYLOAD_COUNT = 256
        const val REPETITIONS = 200
        const val WARMUP_ROUNDS = 4
        const val MEASURED_ROUNDS = 7

        @Volatile
        var benchmarkSink = 0L
    }
}
