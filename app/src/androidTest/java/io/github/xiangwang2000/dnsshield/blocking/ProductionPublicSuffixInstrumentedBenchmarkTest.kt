package io.github.xiangwang2000.dnsshield.blocking

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import kotlin.math.ceil
import kotlin.math.max
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Repeatable on-device characterization for the reviewed production Public Suffix artifact.
 *
 * The artifact is supplied as a generated androidTest asset by benchmark-public-suffix-android.ps1.
 * Measurements are observations only and intentionally have no device-dependent pass/fail limits.
 */
@RunWith(AndroidJUnit4::class)
class ProductionPublicSuffixInstrumentedBenchmarkTest {
    @Test
    fun benchmarkProductionAsset() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val testAssets = instrumentation.context.assets
        val targetContext = instrumentation.targetContext

        val cachedLoader = PublicSuffixAssetLoader.fromAssets(testAssets)
        val cachedFirst = cachedLoader.load()
        val cachedSecond = cachedLoader.load()
        assertSame(cachedFirst, cachedSecond)
        exerciseKnownBoundaries(cachedFirst)
        benchmarkSink = cachedFirst
        forceGc()

        val loadSamples = LongArray(LOAD_ITERATIONS) {
            val loader = PublicSuffixAssetLoader.fromAssets(testAssets)
            measureNanoTime {
                benchmarkSink = loader.load()
            }
        }

        benchmarkSink = null
        forceGc()
        val heapBefore = usedHeapBytes()
        val retainedResolver = PublicSuffixAssetLoader.fromAssets(testAssets).load()
        benchmarkSink = retainedResolver
        forceGc()
        val approximateRetainedHeapBytes = max(0L, usedHeapBytes() - heapBefore)
        exerciseKnownBoundaries(retainedResolver)

        val lookupSamples = LongArray(LOOKUP_BATCHES)
        var checksum = 0
        repeat(LOOKUP_BATCHES) { batch ->
            lookupSamples[batch] = measureNanoTime {
                repeat(LOOKUPS_PER_BATCH) { index ->
                    val query = LOOKUP_CASES[index % LOOKUP_CASES.size].first
                    checksum = checksum xor (
                        retainedResolver.registrableDomain(query)?.hashCode() ?: 0
                    )
                }
            } / LOOKUPS_PER_BATCH
        }
        benchmarkChecksum = checksum

        val artifactBytes = testAssets.open(PublicSuffixAssetLoader.ASSET_NAME).use { it.readBytes() }
        val report = BenchmarkReport(
            model = Build.MODEL ?: "unknown",
            androidRelease = Build.VERSION.RELEASE ?: "unknown",
            apiLevel = Build.VERSION.SDK_INT,
            abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown",
            artifactBytes = artifactBytes.size,
            exactRules = retainedResolver.exactRuleCount,
            wildcardRules = retainedResolver.wildcardRuleCount,
            exceptionRules = retainedResolver.exceptionRuleCount,
            sourceSha256 = retainedResolver.sourceSha256Hex,
            loadIterations = LOAD_ITERATIONS,
            loadMedianNanos = percentile(loadSamples, 0.50),
            loadP95Nanos = percentile(loadSamples, 0.95),
            approximateRetainedHeapBytes = approximateRetainedHeapBytes,
            lookupBatches = LOOKUP_BATCHES,
            lookupsPerBatch = LOOKUPS_PER_BATCH,
            lookupMedianNanos = percentile(lookupSamples, 0.50),
            lookupP95Nanos = percentile(lookupSamples, 0.95)
        )

        assertEquals(153_740, report.artifactBytes)
        assertEquals(9_950, report.exactRules)
        assertEquals(281, report.wildcardRules)
        assertEquals(8, report.exceptionRules)
        assertEquals(
            "72d07fea544b74d920be2394d4c5fbb38dd3f5f3ccac299e27809009bac1c550",
            report.sourceSha256
        )

        val reportDirectory = checkNotNull(targetContext.getExternalFilesDir(null)) {
            "External files directory is unavailable"
        }
        val reportFile = File(reportDirectory, REPORT_FILE_NAME)
        writeReport(reportFile, report.toJson())
        println("DNS_SHIELD_PSL_ANDROID_REPORT=${reportFile.absolutePath}")
        println(report.toJson())
    }

    private fun exerciseKnownBoundaries(resolver: CompiledPublicSuffixList) {
        for ((query, expected) in LOOKUP_CASES) {
            assertEquals(query, expected, resolver.registrableDomain(query))
        }
    }

    private fun usedHeapBytes(): Long {
        val runtime = Runtime.getRuntime()
        return runtime.totalMemory() - runtime.freeMemory()
    }

    private fun forceGc() {
        repeat(3) {
            System.gc()
            Thread.sleep(75)
        }
    }

    private fun percentile(values: LongArray, percentile: Double): Long {
        val sorted = values.sortedArray()
        val index = (ceil(percentile * sorted.size).toInt() - 1).coerceIn(sorted.indices)
        return sorted[index]
    }

    private fun writeReport(reportFile: File, contents: String) {
        reportFile.parentFile?.mkdirs()
        val temporary = File(reportFile.parentFile, reportFile.name + ".tmp")
        temporary.writeText(contents, Charsets.UTF_8)
        if (reportFile.exists() && !reportFile.delete()) {
            throw IllegalStateException("Unable to replace benchmark report: $reportFile")
        }
        if (!temporary.renameTo(reportFile)) {
            throw IllegalStateException("Unable to publish benchmark report: $reportFile")
        }
    }

    private data class BenchmarkReport(
        val model: String,
        val androidRelease: String,
        val apiLevel: Int,
        val abi: String,
        val artifactBytes: Int,
        val exactRules: Int,
        val wildcardRules: Int,
        val exceptionRules: Int,
        val sourceSha256: String,
        val loadIterations: Int,
        val loadMedianNanos: Long,
        val loadP95Nanos: Long,
        val approximateRetainedHeapBytes: Long,
        val lookupBatches: Int,
        val lookupsPerBatch: Int,
        val lookupMedianNanos: Long,
        val lookupP95Nanos: Long
    ) {
        fun toJson(): String = """
            {
              "model": ${model.jsonString()},
              "android_release": ${androidRelease.jsonString()},
              "api_level": $apiLevel,
              "abi": ${abi.jsonString()},
              "artifact_bytes": $artifactBytes,
              "exact_rules": $exactRules,
              "wildcard_rules": $wildcardRules,
              "exception_rules": $exceptionRules,
              "source_sha256": ${sourceSha256.jsonString()},
              "load_iterations": $loadIterations,
              "load_median_nanos": $loadMedianNanos,
              "load_p95_nanos": $loadP95Nanos,
              "approximate_retained_heap_bytes": $approximateRetainedHeapBytes,
              "lookup_batches": $lookupBatches,
              "lookups_per_batch": $lookupsPerBatch,
              "lookup_median_nanos": $lookupMedianNanos,
              "lookup_p95_nanos": $lookupP95Nanos
            }
        """.trimIndent() + "\n"
    }

    companion object {
        const val REPORT_FILE_NAME = "public-suffix.android-benchmark.json"
        private const val LOAD_ITERATIONS = 12
        private const val LOOKUP_BATCHES = 12
        private const val LOOKUPS_PER_BATCH = 20_000

        private val LOOKUP_CASES = listOf(
            "www.example.com" to "example.com",
            "a.b.example.co.uk" to "example.co.uk",
            "ads.tenant.github.io" to "tenant.github.io",
            "cdn.site.blogspot.com" to "site.blogspot.com",
            "a.b.ck" to "a.b.ck",
            "a.www.ck" to "www.ck",
            "a.city.kawasaki.jp" to "city.kawasaki.jp",
            "www.xn--55qx5d.cn" to "www.xn--55qx5d.cn"
        )

        @Volatile
        private var benchmarkSink: Any? = null

        @Volatile
        private var benchmarkChecksum: Int = 0
    }
}

private inline fun measureNanoTime(block: () -> Unit): Long {
    val started = System.nanoTime()
    block()
    return System.nanoTime() - started
}

private fun String.jsonString(): String = buildString(length + 2) {
    append('"')
    for (character in this@jsonString) {
        when (character) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (character.code < 0x20) {
                append("\\u")
                append(character.code.toString(16).padStart(4, '0'))
            } else {
                append(character)
            }
        }
    }
    append('"')
}
