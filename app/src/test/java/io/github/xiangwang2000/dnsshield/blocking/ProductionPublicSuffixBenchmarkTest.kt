package io.github.xiangwang2000.dnsshield.blocking

import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.math.ceil
import kotlin.math.max
import kotlin.system.measureNanoTime
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Opt-in JVM characterization for the generated production Public Suffix artifact.
 *
 * Routine unit tests return immediately unless DNS_SHIELD_PSL_BENCHMARK_ARTIFACT is set. The
 * benchmark writes observations only; it intentionally contains no timing or heap pass/fail gates.
 */
class ProductionPublicSuffixBenchmarkTest {
    @Test
    fun benchmarkGeneratedArtifactWhenRequested() {
        val artifactValue = System.getenv(ARTIFACT_ENV)?.takeIf(String::isNotBlank) ?: return
        val artifactPath = Paths.get(artifactValue).toAbsolutePath().normalize()
        require(Files.isRegularFile(artifactPath)) {
            "Production Public Suffix artifact not found: $artifactPath"
        }
        val reportPath = System.getenv(REPORT_ENV)
            ?.takeIf(String::isNotBlank)
            ?.let(Paths::get)
            ?.toAbsolutePath()
            ?.normalize()
            ?: Paths.get("build", "public-suffix.benchmark.json")
                .toAbsolutePath()
                .normalize()
        val artifact = Files.readAllBytes(artifactPath)

        // Load once before measurements so class loading and basic JIT work do not dominate samples.
        benchmarkSink = loadResolver(artifact)
        exerciseKnownBoundaries(checkNotNull(benchmarkSink as? CompiledPublicSuffixList))
        forceGc()

        val loadSamples = LongArray(LOAD_ITERATIONS) {
            measureNanoTime {
                benchmarkSink = loadResolver(artifact)
            }
        }

        benchmarkSink = null
        forceGc()
        val heapBefore = usedHeapBytes()
        val retainedResolver = loadResolver(artifact)
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

        val report = BenchmarkReport(
            artifactPath = artifactPath.toString(),
            artifactBytes = artifact.size,
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
            lookupP95Nanos = percentile(lookupSamples, 0.95),
            javaVersion = System.getProperty("java.version") ?: "unknown",
            osName = System.getProperty("os.name") ?: "unknown"
        )
        writeReport(reportPath, report)
        println("Public Suffix benchmark report: $reportPath")
    }

    private fun exerciseKnownBoundaries(resolver: CompiledPublicSuffixList) {
        for ((query, expected) in LOOKUP_CASES) {
            assertEquals(expected, resolver.registrableDomain(query), query)
        }
    }

    private fun loadResolver(artifact: ByteArray): CompiledPublicSuffixList =
        CompiledPublicSuffixList.fromByteBuffer(ByteBuffer.wrap(artifact))

    private fun usedHeapBytes(): Long {
        val runtime = Runtime.getRuntime()
        return runtime.totalMemory() - runtime.freeMemory()
    }

    private fun forceGc() {
        repeat(3) {
            System.gc()
            Thread.sleep(50)
        }
    }

    private fun percentile(values: LongArray, percentile: Double): Long {
        require(values.isNotEmpty())
        val sorted = values.sortedArray()
        val index = (ceil(percentile * sorted.size).toInt() - 1).coerceIn(sorted.indices)
        return sorted[index]
    }

    private fun writeReport(path: Path, report: BenchmarkReport) {
        path.parent?.let(Files::createDirectories)
        val temporary = path.resolveSibling(path.fileName.toString() + ".tmp")
        Files.writeString(temporary, report.toJson())
        try {
            Files.move(
                temporary,
                path,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE
            )
        } catch (_: java.nio.file.AtomicMoveNotSupportedException) {
            Files.move(
                temporary,
                path,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING
            )
        }
    }

    private data class BenchmarkReport(
        val artifactPath: String,
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
        val lookupP95Nanos: Long,
        val javaVersion: String,
        val osName: String
    ) {
        fun toJson(): String = """
            {
              "artifact_path": ${artifactPath.jsonString()},
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
              "lookup_p95_nanos": $lookupP95Nanos,
              "java_version": ${javaVersion.jsonString()},
              "os_name": ${osName.jsonString()}
            }
        """.trimIndent() + "\n"
    }

    companion object {
        private const val ARTIFACT_ENV = "DNS_SHIELD_PSL_BENCHMARK_ARTIFACT"
        private const val REPORT_ENV = "DNS_SHIELD_PSL_BENCHMARK_REPORT"
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
