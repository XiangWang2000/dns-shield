package io.github.xiangwang2000.dnsshield.blocking

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import android.util.Base64
import kotlin.math.ceil
import kotlin.math.max
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device characterization for the production runtime-policy path introduced by PR #24.
 *
 * This benchmark uses the checked-in main APK Public Suffix asset and the same four-entry active.bin
 * fixture as ActiveBlocklistRuntimeInstrumentedTest. Measurements are observations only; no
 * device-dependent performance threshold is asserted here.
 */
@RunWith(AndroidJUnit4::class)
class RuntimeDomainPolicyInstrumentedBenchmarkTest {
    @Test
    fun benchmarkRuntimePolicyAssemblyAndMatching() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val targetContext = instrumentation.targetContext
        val filesDirectory = targetContext.filesDir
        val activeFile = RuntimeDomainPolicy.activeBlocklistFile(filesDirectory)

        removeActiveFile(activeFile)
        try {
            var missingProviderCalls = 0
            val missingAssemblySamples = LongArray(ASSEMBLY_ITERATIONS) {
                measureNanos {
                    benchmarkSink = RuntimeDomainPolicy.assemble(
                        filesDirectory = filesDirectory,
                        registrableDomainResolverProvider = {
                            missingProviderCalls++
                            error("Resolver provider must remain lazy when active.bin is missing")
                        }
                    )
                }
            }
            assertEquals(0, missingProviderCalls)
            val missingAssembly = benchmarkSink as DomainPolicyAssembly
            assertEquals(CompiledBlocklistStatus.NotConfigured, missingAssembly.compiledBlocklistStatus)
            assertTrue(missingAssembly.matcher.shouldBlock("admob.com"))
            assertFalse(missingAssembly.matcher.shouldBlock("github.com"))

            writeFixture(activeFile)

            benchmarkSink = null
            forceGc()
            val heapBeforeActivePolicy = usedHeapBytes()

            val resolverOwner = PublicSuffixResolverOwner.fromAssets(targetContext.assets)
            var firstActiveAssembly: DomainPolicyAssembly? = null
            val firstActiveAssemblyNanos = measureNanos {
                firstActiveAssembly = RuntimeDomainPolicy.assemble(
                    filesDirectory = filesDirectory,
                    registrableDomainResolverProvider = resolverOwner::resolverOrNull
                )
            }
            val activeAssembly = checkNotNull(firstActiveAssembly)
            benchmarkSink = ActivePolicyRetention(resolverOwner, activeAssembly)
            forceGc()
            val approximateActivePolicyRetainedHeapBytes =
                max(0L, usedHeapBytes() - heapBeforeActivePolicy)

            assertEquals(
                CompiledBlocklistStatus.Loaded(entryCount = ACTIVE_FIXTURE_ENTRIES),
                activeAssembly.compiledBlocklistStatus
            )
            assertEquals(
                PublicSuffixResolverStatus.Loaded(
                    exactRules = 9_950,
                    wildcardRules = 281,
                    exceptionRules = 8
                ),
                resolverOwner.status()
            )
            assertTrue(activeAssembly.matcher.shouldBlock("github.com"))
            assertTrue(activeAssembly.matcher.shouldBlock("cdn.github.com"))
            assertFalse(activeAssembly.matcher.shouldBlock("example.com"))

            val cachedActiveAssemblySamples = LongArray(ASSEMBLY_ITERATIONS) {
                measureNanos {
                    benchmarkSink = RuntimeDomainPolicy.assemble(
                        filesDirectory = filesDirectory,
                        registrableDomainResolverProvider = resolverOwner::resolverOrNull
                    )
                }
            }

            val exactLookupSamples = benchmarkLookups(activeAssembly, "github.com", expectedBlocked = true)
            val parentLookupSamples = benchmarkLookups(activeAssembly, "cdn.github.com", expectedBlocked = true)
            val unrelatedLookupSamples = benchmarkLookups(activeAssembly, "example.com", expectedBlocked = false)

            val resolverStatus = resolverOwner.status() as PublicSuffixResolverStatus.Loaded
            val report = BenchmarkReport(
                model = Build.MODEL ?: "unknown",
                androidRelease = Build.VERSION.RELEASE ?: "unknown",
                apiLevel = Build.VERSION.SDK_INT,
                abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown",
                activeFixtureEntries = ACTIVE_FIXTURE_ENTRIES,
                missingAssemblyIterations = ASSEMBLY_ITERATIONS,
                missingAssemblyMedianNanos = percentile(missingAssemblySamples, 0.50),
                missingAssemblyP95Nanos = percentile(missingAssemblySamples, 0.95),
                firstActiveAssemblyNanos = firstActiveAssemblyNanos,
                cachedActiveAssemblyIterations = ASSEMBLY_ITERATIONS,
                cachedActiveAssemblyMedianNanos = percentile(cachedActiveAssemblySamples, 0.50),
                cachedActiveAssemblyP95Nanos = percentile(cachedActiveAssemblySamples, 0.95),
                approximateActivePolicyRetainedHeapBytes = approximateActivePolicyRetainedHeapBytes,
                lookupBatches = LOOKUP_BATCHES,
                lookupsPerBatch = LOOKUPS_PER_BATCH,
                exactLookupMedianNanos = percentile(exactLookupSamples, 0.50),
                exactLookupP95Nanos = percentile(exactLookupSamples, 0.95),
                parentLookupMedianNanos = percentile(parentLookupSamples, 0.50),
                parentLookupP95Nanos = percentile(parentLookupSamples, 0.95),
                unrelatedLookupMedianNanos = percentile(unrelatedLookupSamples, 0.50),
                unrelatedLookupP95Nanos = percentile(unrelatedLookupSamples, 0.95),
                publicSuffixExactRules = resolverStatus.exactRules,
                publicSuffixWildcardRules = resolverStatus.wildcardRules,
                publicSuffixExceptionRules = resolverStatus.exceptionRules
            )

            val reportDirectory = checkNotNull(targetContext.getExternalFilesDir(null)) {
                "External files directory is unavailable"
            }
            val reportFile = File(reportDirectory, REPORT_FILE_NAME)
            writeReport(reportFile, report.toJson())
            println("DNS_SHIELD_RUNTIME_POLICY_ANDROID_REPORT=${reportFile.absolutePath}")
            println(report.toJson())
        } finally {
            benchmarkSink = null
            removeActiveFile(activeFile)
        }
    }

    private fun benchmarkLookups(
        assembly: DomainPolicyAssembly,
        domain: String,
        expectedBlocked: Boolean
    ): LongArray {
        assertEquals(expectedBlocked, assembly.matcher.shouldBlock(domain))
        val samples = LongArray(LOOKUP_BATCHES)
        var checksum = 0
        repeat(WARMUP_BATCHES) {
            repeat(LOOKUPS_PER_BATCH) {
                if (assembly.matcher.shouldBlock(domain)) {
                    checksum = checksum xor domain.hashCode()
                }
            }
        }
        repeat(LOOKUP_BATCHES) { batch ->
            samples[batch] = measureNanos {
                repeat(LOOKUPS_PER_BATCH) {
                    if (assembly.matcher.shouldBlock(domain)) {
                        checksum = checksum xor domain.hashCode()
                    }
                }
            } / LOOKUPS_PER_BATCH
        }
        benchmarkChecksum = checksum
        return samples
    }

    private fun writeFixture(activeFile: File) {
        val parentDirectory = requireNotNull(activeFile.parentFile)
        check(parentDirectory.isDirectory || parentDirectory.mkdirs())
        activeFile.writeBytes(Base64.decode(ACTIVE_FIXTURE_BASE64, Base64.DEFAULT))
    }

    private fun removeActiveFile(activeFile: File) {
        if (activeFile.isDirectory) {
            check(activeFile.deleteRecursively())
        } else if (activeFile.exists()) {
            check(activeFile.delete())
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

    private data class ActivePolicyRetention(
        val resolverOwner: PublicSuffixResolverOwner,
        val assembly: DomainPolicyAssembly
    )

    private data class BenchmarkReport(
        val model: String,
        val androidRelease: String,
        val apiLevel: Int,
        val abi: String,
        val activeFixtureEntries: Int,
        val missingAssemblyIterations: Int,
        val missingAssemblyMedianNanos: Long,
        val missingAssemblyP95Nanos: Long,
        val firstActiveAssemblyNanos: Long,
        val cachedActiveAssemblyIterations: Int,
        val cachedActiveAssemblyMedianNanos: Long,
        val cachedActiveAssemblyP95Nanos: Long,
        val approximateActivePolicyRetainedHeapBytes: Long,
        val lookupBatches: Int,
        val lookupsPerBatch: Int,
        val exactLookupMedianNanos: Long,
        val exactLookupP95Nanos: Long,
        val parentLookupMedianNanos: Long,
        val parentLookupP95Nanos: Long,
        val unrelatedLookupMedianNanos: Long,
        val unrelatedLookupP95Nanos: Long,
        val publicSuffixExactRules: Int,
        val publicSuffixWildcardRules: Int,
        val publicSuffixExceptionRules: Int
    ) {
        fun toJson(): String = """
            {
              "model": ${model.jsonString()},
              "android_release": ${androidRelease.jsonString()},
              "api_level": $apiLevel,
              "abi": ${abi.jsonString()},
              "active_fixture_entries": $activeFixtureEntries,
              "missing_assembly_iterations": $missingAssemblyIterations,
              "missing_assembly_median_nanos": $missingAssemblyMedianNanos,
              "missing_assembly_p95_nanos": $missingAssemblyP95Nanos,
              "first_active_assembly_nanos": $firstActiveAssemblyNanos,
              "cached_active_assembly_iterations": $cachedActiveAssemblyIterations,
              "cached_active_assembly_median_nanos": $cachedActiveAssemblyMedianNanos,
              "cached_active_assembly_p95_nanos": $cachedActiveAssemblyP95Nanos,
              "approximate_active_policy_retained_heap_bytes": $approximateActivePolicyRetainedHeapBytes,
              "lookup_batches": $lookupBatches,
              "lookups_per_batch": $lookupsPerBatch,
              "exact_lookup_median_nanos": $exactLookupMedianNanos,
              "exact_lookup_p95_nanos": $exactLookupP95Nanos,
              "parent_lookup_median_nanos": $parentLookupMedianNanos,
              "parent_lookup_p95_nanos": $parentLookupP95Nanos,
              "unrelated_lookup_median_nanos": $unrelatedLookupMedianNanos,
              "unrelated_lookup_p95_nanos": $unrelatedLookupP95Nanos,
              "public_suffix_exact_rules": $publicSuffixExactRules,
              "public_suffix_wildcard_rules": $publicSuffixWildcardRules,
              "public_suffix_exception_rules": $publicSuffixExceptionRules
            }
        """.trimIndent() + "\n"
    }

    companion object {
        const val REPORT_FILE_NAME = "runtime-domain-policy.android-benchmark.json"
        private const val ASSEMBLY_ITERATIONS = 20
        private const val LOOKUP_BATCHES = 20
        private const val LOOKUPS_PER_BATCH = 20_000
        private const val WARMUP_BATCHES = 2
        private const val ACTIVE_FIXTURE_ENTRIES = 4
        private const val ACTIVE_FIXTURE_BASE64 =
            "RE5TSEJMMDEBAAAAAQAAAAQAAAAAAAAAWV11x9vzG2vNdXcSzQSM3HjfSXkCaJ7dZDit/w2/NO0="

        @Volatile
        private var benchmarkSink: Any? = null

        @Volatile
        private var benchmarkChecksum: Int = 0
    }
}

private inline fun measureNanos(block: () -> Unit): Long {
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
