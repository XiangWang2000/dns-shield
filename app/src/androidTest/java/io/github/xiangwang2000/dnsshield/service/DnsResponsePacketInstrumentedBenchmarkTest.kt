package io.github.xiangwang2000.dnsshield.service

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import kotlin.math.ceil
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Paired on-device benchmark for removing the pre-packet DNS response copy. */
@RunWith(AndroidJUnit4::class)
class DnsResponsePacketInstrumentedBenchmarkTest {
    @Test
    fun benchmarkLegacyAndSingleCopyPacketBuilds() {
        val responses = RESPONSE_SIZES.map { size -> ByteArray(size) { it.toByte() } }
        val transactionIds = responses.indices.map { index ->
            byteArrayOf((index + 1).toByte(), (index + 17).toByte())
        }
        responses.indices.forEach { index ->
            assertArrayEquals(
                legacyBuild(responses[index], transactionIds[index]),
                currentBuild(responses[index], transactionIds[index])
            )
        }

        repeat(WARMUP_BATCHES) {
            runLegacyBatch(responses, transactionIds)
            runCurrentBatch(responses, transactionIds)
        }
        val legacySamples = LongArray(SAMPLE_BATCHES)
        val currentSamples = LongArray(SAMPLE_BATCHES)
        repeat(SAMPLE_BATCHES) { index ->
            if (index % 2 == 0) {
                legacySamples[index] = measureNanos { runLegacyBatch(responses, transactionIds) }
                currentSamples[index] = measureNanos { runCurrentBatch(responses, transactionIds) }
            } else {
                currentSamples[index] = measureNanos { runCurrentBatch(responses, transactionIds) }
                legacySamples[index] = measureNanos { runLegacyBatch(responses, transactionIds) }
            }
        }

        val queriesPerBatch = RESPONSE_SIZES.size.toLong() * REPETITIONS
        val report = """
            {
              "model": "${android.os.Build.MODEL}",
              "queries_per_batch": $queriesPerBatch,
              "sample_batches": $SAMPLE_BATCHES,
              "average_response_bytes": ${RESPONSE_SIZES.average()},
              "legacy_extra_response_copies_per_query": 1,
              "current_extra_response_copies_per_query": 0,
              "legacy_median_nanos_per_query": ${median(legacySamples) / queriesPerBatch},
              "current_median_nanos_per_query": ${median(currentSamples) / queriesPerBatch},
              "legacy_p95_nanos_per_query": ${percentile(legacySamples, 0.95) / queriesPerBatch},
              "current_p95_nanos_per_query": ${percentile(currentSamples, 0.95) / queriesPerBatch}
            }
        """.trimIndent() + "\n"
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val reportFile = File(checkNotNull(context.getExternalFilesDir(null)), REPORT_FILE_NAME)
        reportFile.writeText(report, Charsets.UTF_8)
        println("DNS_SHIELD_RESPONSE_PACKET_ANDROID_REPORT=${reportFile.absolutePath}")
        println(report)
        assertTrue(benchmarkSink != 0L)
    }

    private fun runLegacyBatch(responses: List<ByteArray>, ids: List<ByteArray>) {
        var sink = 0L
        repeat(REPETITIONS) {
            responses.indices.forEach { index ->
                val packet = legacyBuild(responses[index], ids[index])
                sink += packet[28].toLong() + packet[packet.lastIndex]
            }
        }
        benchmarkSink = sink
    }

    private fun runCurrentBatch(responses: List<ByteArray>, ids: List<ByteArray>) {
        var sink = 0L
        repeat(REPETITIONS) {
            responses.indices.forEach { index ->
                val packet = currentBuild(responses[index], ids[index])
                sink += packet[28].toLong() + packet[packet.lastIndex]
            }
        }
        benchmarkSink = sink
    }

    private fun legacyBuild(response: ByteArray, transactionId: ByteArray): ByteArray {
        val stampedResponse = response.copyOf()
        if (stampedResponse.size >= 2) {
            stampedResponse[0] = transactionId[0]
            stampedResponse[1] = transactionId[1]
        }
        return DnsResponsePacketBuilder.build(
            SOURCE_IP,
            DESTINATION_IP,
            53,
            53000,
            stampedResponse
        )
    }

    private fun currentBuild(response: ByteArray, transactionId: ByteArray): ByteArray =
        DnsResponsePacketBuilder.build(
            SOURCE_IP,
            DESTINATION_IP,
            53,
            53000,
            response,
            transactionId
        )

    private fun median(values: LongArray): Long = percentile(values, 0.5)

    private fun percentile(values: LongArray, percentile: Double): Long {
        val sorted = values.sortedArray()
        val index = (ceil(percentile * sorted.size).toInt() - 1).coerceIn(sorted.indices)
        return sorted[index]
    }

    private companion object {
        const val REPORT_FILE_NAME = "dns-response-packet.android-benchmark.json"
        val RESPONSE_SIZES = listOf(64, 128, 512, 1500)
        val SOURCE_IP = byteArrayOf(10, 0, 0, 1)
        val DESTINATION_IP = byteArrayOf(10, 0, 0, 2)
        const val REPETITIONS = 2_000
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
