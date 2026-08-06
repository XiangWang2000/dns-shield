package io.github.xiangwang2000.dnsshield.blocking

import android.os.Debug
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import kotlin.math.ceil
import kotlin.system.measureNanoTime
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PublicSuffixArtifactInstrumentedBenchmarkTest {
    @Test
    fun characterizeProductionArtifact() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val arguments = InstrumentationRegistry.getArguments()
        val artifactName = arguments.getString("pslArtifact") ?: "public-suffix.bin"
        val loadIterations = arguments.getString("pslLoadIterations")?.toIntOrNull() ?: 12
        val lookupBatches = arguments.getString("pslLookupBatches")?.toIntOrNull() ?: 12
        val lookupsPerBatch = arguments.getString("pslLookupsPerBatch")?.toIntOrNull() ?: 20_000
        require(loadIterations >= 2)
        require(lookupBatches >= 2)
        require(lookupsPerBatch > 0)

        val artifact = File(context.filesDir, artifactName)
        require(artifact.isFile) { "Missing benchmark artifact: ${artifact.absolutePath}" }

        var loaded = PublicSuffixArtifactLoader.loadProduction(artifact.inputStream())
        verifyBoundaries(loaded.resolver)
        forceGc()

        val loadSamples = LongArray(loadIterations) {
            measureNanoTime {
                loaded = PublicSuffixArtifactLoader.loadProduction(artifact.inputStream())
            }
        }

        forceGc()
        val heapBefore = Debug.getNativeHeapAllocatedSize() + usedJavaHeap()
        loaded = PublicSuffixArtifactLoader.loadProduction(artifact.inputStream())
        forceGc()
        val approximateHeapBytes =
            (Debug.getNativeHeapAllocatedSize() + usedJavaHeap() - heapBefore).coerceAtLeast(0L)

        val lookupSamples = LongArray(lookupBatches)
        var checksum = 0
        repeat(lookupBatches) { batch ->
            lookupSamples[batch] = measureNanoTime {
                repeat(lookupsPerBatch) { index ->
                    val query = LOOKUP_CASES[index % LOOKUP_CASES.size].first
                    checksum = checksum xor (loaded.resolver.registrableDomain(query)?.hashCode() ?: 0)
                }
            } / lookupsPerBatch
        }

        val report = """
            {
              "device": ${android.os.Build.MODEL.json()},
              "android_api": ${android.os.Build.VERSION.SDK_INT},
              "abi": ${android.os.Build.SUPPORTED_ABIS.firstOrNull().orEmpty().json()},
              "artifact_bytes": ${loaded.artifactBytes},
              "artifact_sha256": ${loaded.artifactSha256.json()},
              "exact_rules": ${loaded.resolver.exactRuleCount},
              "wildcard_rules": ${loaded.resolver.wildcardRuleCount},
              "exception_rules": ${loaded.resolver.exceptionRuleCount},
              "load_iterations": $loadIterations,
              "load_median_nanos": ${percentile(loadSamples, 0.50)},
              "load_p95_nanos": ${percentile(loadSamples, 0.95)},
              "approximate_heap_bytes": $approximateHeapBytes,
              "lookup_batches": $lookupBatches,
              "lookups_per_batch": $lookupsPerBatch,
              "lookup_median_nanos": ${percentile(lookupSamples, 0.50)},
              "lookup_p95_nanos": ${percentile(lookupSamples, 0.95)},
              "checksum": $checksum
            }
        """.trimIndent() + "\n"

        File(context.filesDir, "public-suffix.android-benchmark.json").writeText(report)
        Log.i(TAG, report)
    }

    private fun verifyBoundaries(resolver: CompiledPublicSuffixList) {
        LOOKUP_CASES.forEach { (query, expected) ->
            assertEquals(query, expected, resolver.registrableDomain(query))
        }
    }

    private fun usedJavaHeap(): Long {
        val runtime = Runtime.getRuntime()
        return runtime.totalMemory() - runtime.freeMemory()
    }

    private fun forceGc() {
        repeat(3) {
            Runtime.getRuntime().gc()
            Thread.sleep(100)
        }
    }

    private fun percentile(values: LongArray, percentile: Double): Long {
        val sorted = values.sortedArray()
        val index = (ceil(percentile * sorted.size).toInt() - 1).coerceIn(sorted.indices)
        return sorted[index]
    }

    companion object {
        private const val TAG = "DnsShieldPslBenchmark"
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
    }
}

private fun String.json(): String = buildString(length + 2) {
    append('"')
    for (character in this@json) {
        when (character) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> append(character)
        }
    }
    append('"')
}
