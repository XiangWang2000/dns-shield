package io.github.xiangwang2000.dnsshield.service

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.ceil
import okhttp3.Call
import okhttp3.Callback
import okhttp3.ConnectionPool
import okhttp3.Dispatcher
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Real-network paired benchmark for OkHttp's per-host DoH burst queue. */
@RunWith(AndroidJUnit4::class)
class DohBurstInstrumentedBenchmarkTest {
    @Test
    fun benchmarkDefaultAndAlignedPerHostLimits() {
        val defaultClient = client(DEFAULT_MAX_REQUESTS_PER_HOST)
        val alignedClient = client(ALIGNED_MAX_REQUESTS_PER_HOST)
        warmUp(defaultClient)
        warmUp(alignedClient)

        val defaultSamples = LongArray(SAMPLE_BATCHES)
        val alignedSamples = LongArray(SAMPLE_BATCHES)
        repeat(SAMPLE_BATCHES) { index ->
            if (index % 2 == 0) {
                defaultSamples[index] = runBatch(defaultClient, "default-$index")
                alignedSamples[index] = runBatch(alignedClient, "aligned-$index")
            } else {
                alignedSamples[index] = runBatch(alignedClient, "aligned-$index")
                defaultSamples[index] = runBatch(defaultClient, "default-$index")
            }
        }

        val report = """
            {
              "model": "${android.os.Build.MODEL}",
              "requests_per_batch": $REQUESTS_PER_BATCH,
              "sample_batches": $SAMPLE_BATCHES,
              "default_max_requests_per_host": $DEFAULT_MAX_REQUESTS_PER_HOST,
              "aligned_max_requests_per_host": $ALIGNED_MAX_REQUESTS_PER_HOST,
              "default_median_millis": ${median(defaultSamples)},
              "aligned_median_millis": ${median(alignedSamples)},
              "default_p95_millis": ${percentile(defaultSamples, 0.95)},
              "aligned_p95_millis": ${percentile(alignedSamples, 0.95)}
            }
        """.trimIndent() + "\n"
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val reportFile = File(checkNotNull(context.getExternalFilesDir(null)), REPORT_FILE_NAME)
        reportFile.writeText(report, Charsets.UTF_8)
        println("DNS_SHIELD_DOH_BURST_ANDROID_REPORT=${reportFile.absolutePath}")
        println(report)
    }

    private fun client(maxRequestsPerHost: Int): OkHttpClient {
        val dispatcher = Dispatcher().apply {
            maxRequests = ALIGNED_MAX_REQUESTS_PER_HOST
            this.maxRequestsPerHost = maxRequestsPerHost
        }
        return OkHttpClient.Builder()
            .dns(DohBootstrapDns)
            .dispatcher(dispatcher)
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(3, TimeUnit.SECONDS)
            .writeTimeout(3, TimeUnit.SECONDS)
            .connectionPool(ConnectionPool(5, 5, TimeUnit.MINUTES))
            .build()
    }

    private fun warmUp(client: OkHttpClient) {
        val successes = AtomicInteger()
        val latch = CountDownLatch(1)
        enqueue(client, dnsQuery("warmup.example.com", 1), latch, successes)
        check(latch.await(BATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS))
        assertEquals(1, successes.get())
    }

    private fun runBatch(client: OkHttpClient, batch: String): Long {
        val successes = AtomicInteger()
        val latch = CountDownLatch(REQUESTS_PER_BATCH)
        val started = System.nanoTime()
        repeat(REQUESTS_PER_BATCH) { index ->
            enqueue(
                client,
                dnsQuery("$batch-$index.example.com", index + 2),
                latch,
                successes
            )
        }
        check(latch.await(BATCH_TIMEOUT_SECONDS, TimeUnit.SECONDS))
        val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        assertEquals(REQUESTS_PER_BATCH, successes.get())
        return elapsedMillis
    }

    private fun enqueue(
        client: OkHttpClient,
        payload: ByteArray,
        latch: CountDownLatch,
        successes: AtomicInteger
    ) {
        val request = Request.Builder()
            .url(DOH_URL)
            .header("Content-Type", DNS_MEDIA_TYPE_VALUE)
            .header("Accept", DNS_MEDIA_TYPE_VALUE)
            .post(payload.toRequestBody(DNS_MEDIA_TYPE))
            .build()
        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: java.io.IOException) {
                latch.countDown()
            }

            override fun onResponse(call: Call, response: Response) {
                try {
                    response.use {
                        val body = response.body.bytes()
                        if (response.isSuccessful && body.size >= 12) successes.incrementAndGet()
                    }
                } finally {
                    latch.countDown()
                }
            }
        })
    }

    private fun dnsQuery(domain: String, transactionId: Int): ByteArray {
        val labels = domain.split('.')
        val size = 12 + labels.sumOf { it.length + 1 } + 1 + 4
        val query = ByteArray(size)
        query[0] = (transactionId ushr 8).toByte()
        query[1] = transactionId.toByte()
        query[2] = 0x01
        query[5] = 0x01
        var offset = 12
        labels.forEach { label ->
            query[offset++] = label.length.toByte()
            label.encodeToByteArray().copyInto(query, offset)
            offset += label.length
        }
        offset++
        query[offset + 1] = 0x01
        query[offset + 3] = 0x01
        return query
    }

    private fun median(values: LongArray): Long = percentile(values, 0.5)

    private fun percentile(values: LongArray, percentile: Double): Long {
        val sorted = values.sortedArray()
        val index = (ceil(percentile * sorted.size).toInt() - 1).coerceIn(sorted.indices)
        return sorted[index]
    }

    private companion object {
        const val REPORT_FILE_NAME = "doh-burst.android-benchmark.json"
        const val DOH_URL = "https://dns.google/dns-query"
        const val DNS_MEDIA_TYPE_VALUE = "application/dns-message"
        val DNS_MEDIA_TYPE = DNS_MEDIA_TYPE_VALUE.toMediaType()
        const val REQUESTS_PER_BATCH = 24
        const val SAMPLE_BATCHES = 7
        const val DEFAULT_MAX_REQUESTS_PER_HOST = 5
        const val ALIGNED_MAX_REQUESTS_PER_HOST = 24
        const val BATCH_TIMEOUT_SECONDS = 15L
    }
}
