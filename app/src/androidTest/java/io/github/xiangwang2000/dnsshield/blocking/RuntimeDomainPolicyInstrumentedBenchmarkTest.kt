package io.github.xiangwang2000.dnsshield.blocking

import android.os.Build
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
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

            val coldMeasurement = measureColdActivePolicy(filesDirectory, targetContext.assets)

            // PR #25 took its heap baseline before the first PSL/asset/parser construction, so that
            // number also includes one-time class/static initialization. After the cold measurement
            // has completed and its retained objects have been released, take repeated steady-state
            // measurements with the same code paths already initialized.
            benchmarkSink = null
            forceGc()
            val steadyHeapMeasurement = measureSteadyStateHeap(filesDirectory, targetContext.assets)

            val report = BenchmarkReport(
                model = Build.MODEL ?: "unknown",
                androidRelease = Build.VERSION.RELEASE ?: "unknown",
                apiLevel = Build.VERSION.SDK_INT,
                abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown",
                activeFixtureEntries = ACTIVE_FIXTURE_ENTRIES,
                missingAssemblyIterations = ASSEMBLY_ITERATIONS,
                missingAssemblyMedianNanos = percentile(missingAssemblySamples, 0.50),
                missingAssemblyP95Nanos = percentile(missingAssemblySamples, 0.95),
                firstActiveAssemblyNanos = coldMeasurement.firstActiveAssemblyNanos,
                cachedActiveAssemblyIterations = ASSEMBLY_ITERATIONS,
                cachedActiveAssemblyMedianNanos = percentile(coldMeasurement.cachedAssemblySamples, 0.50),
                cachedActiveAssemblyP95Nanos = percentile(coldMeasurement.cachedAssemblySamples, 0.95),
                // Preserve the PR #25 field for report compatibility. It is intentionally the
                // cold-inclusive delta and must not be treated as steady retained object size.
                approximateActivePolicyRetainedHeapBytes = coldMeasurement.coldInclusiveHeapDeltaBytes,
                steadyHeapIterations = HEAP_ITERATIONS,
                steadyExactPolicyRetainedHeapMedianBytes =
                    percentile(steadyHeapMeasurement.exactPolicySamples, 0.50),
                steadyParentPolicyRetainedHeapMedianBytes =
                    percentile(steadyHeapMeasurement.parentPolicySamples, 0.50),
                steadyParentIncrementalHeapMedianBytes =
                    percentile(steadyHeapMeasurement.parentIncrementalSamples, 0.50),
                lookupBatches = LOOKUP_BATCHES,
                lookupsPerBatch = LOOKUPS_PER_BATCH,
                exactLookupMedianNanos = percentile(coldMeasurement.exactLookupSamples, 0.50),
                exactLookupP95Nanos = percentile(coldMeasurement.exactLookupSamples, 0.95),
                parentLookupMedianNanos = percentile(coldMeasurement.parentLookupSamples, 0.50),
                parentLookupP95Nanos = percentile(coldMeasurement.parentLookupSamples, 0.95),
                unrelatedLookupMedianNanos = percentile(coldMeasurement.unrelatedLookupSamples, 0.50),
                unrelatedLookupP95Nanos = percentile(coldMeasurement.unrelatedLookupSamples, 0.95),
                publicSuffixExactRules = coldMeasurement.resolverStatus.exactRules,
                publicSuffixWildcardRules = coldMeasurement.resolverStatus.wildcardRules,
                publicSuffixExceptionRules = coldMeasurement.resolverStatus.exceptionRules
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

    private fun measureColdActivePolicy(
        filesDirectory: File,
        assets: android.content.res.AssetManager
    ): ColdActiveMeasurement {
        benchmarkSink = null
        forceGc()
        val heapBeforeActivePolicy = usedHeapBytes()

        val resolverOwner = PublicSuffixResolverOwner.fromAssets(assets)
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
        val coldInclusiveHeapDeltaBytes = max(0L, usedHeapBytes() - heapBeforeActivePolicy)

        assertActivePolicy(activeAssembly, resolverOwner)

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

        benchmarkSink = null
        return ColdActiveMeasurement(
            firstActiveAssemblyNanos = firstActiveAssemblyNanos,
            coldInclusiveHeapDeltaBytes = coldInclusiveHeapDeltaBytes,
            cachedAssemblySamples = cachedActiveAssemblySamples,
            exactLookupSamples = exactLookupSamples,
            parentLookupSamples = parentLookupSamples,
            unrelatedLookupSamples = unrelatedLookupSamples,
            resolverStatus = resolverStatus
        )
    }

    private fun measureSteadyStateHeap(
        filesDirectory: File,
        assets: android.content.res.AssetManager
    ): SteadyHeapMeasurement {
        // One unmeasured warm construction ensures provider/AssetManager/SHA/parser/resolver classes
        // and their static state have already been initialized before steady retained-heap baselines.
        val warmOwner = PublicSuffixResolverOwner.fromAssets(assets)
        val warmAssembly = RuntimeDomainPolicy.assemble(
            filesDirectory = filesDirectory,
            registrableDomainResolverProvider = warmOwner::resolverOrNull
        )
        assertActivePolicy(warmAssembly, warmOwner)
        benchmarkSink = ActivePolicyRetention(warmOwner, warmAssembly)
        forceGc()
        benchmarkSink = null
        forceGc()

        val exactPolicySamples = LongArray(HEAP_ITERATIONS)
        val parentPolicySamples = LongArray(HEAP_ITERATIONS)
        val parentIncrementalSamples = LongArray(HEAP_ITERATIONS)

        repeat(HEAP_ITERATIONS) { index ->
            exactPolicySamples[index] = measureSteadyExactPolicyHeap(filesDirectory)
            parentPolicySamples[index] = measureSteadyParentPolicyHeap(filesDirectory, assets)
            parentIncrementalSamples[index] =
                max(0L, parentPolicySamples[index] - exactPolicySamples[index])
        }

        return SteadyHeapMeasurement(
            exactPolicySamples = exactPolicySamples,
            parentPolicySamples = parentPolicySamples,
            parentIncrementalSamples = parentIncrementalSamples
        )
    }

    private fun measureSteadyExactPolicyHeap(filesDirectory: File): Long {
        benchmarkSink = null
        forceGc()
        val heapBefore = usedHeapBytes()
        val exactAssembly = RuntimeDomainPolicy.assemble(
            filesDirectory = filesDirectory,
            registrableDomainResolverProvider = { null }
        )
        assertEquals(
            CompiledBlocklistStatus.Loaded(entryCount = ACTIVE_FIXTURE_ENTRIES),
            exactAssembly.compiledBlocklistStatus
        )
        assertTrue(exactAssembly.matcher.shouldBlock("github.com"))
        assertFalse(exactAssembly.matcher.shouldBlock("cdn.github.com"))
        benchmarkSink = exactAssembly
        forceGc()
        val retainedBytes = max(0L, usedHeapBytes() - heapBefore)
        benchmarkSink = null
        return retainedBytes
    }

    private fun measureSteadyParentPolicyHeap(
        filesDirectory: File,
        assets: android.content.res.AssetManager
    ): Long {
        benchmarkSink = null
        forceGc()
        val heapBefore = usedHeapBytes()
        val resolverOwner = PublicSuffixResolverOwner.fromAssets(assets)
        val activeAssembly = RuntimeDomainPolicy.assemble(
            filesDirectory = filesDirectory,
            registrableDomainResolverProvider = resolverOwner::resolverOrNull
        )
        assertActivePolicy(activeAssembly, resolverOwner)
        benchmarkSink = ActivePolicyRetention(resolverOwner, activeAssembly)
        forceGc()
        val retainedBytes = max(0L, usedHeapBytes() - heapBefore)
        benchmarkSink = null
        return retainedBytes
    }

    private fun assertActivePolicy(
        assembly: DomainPolicyAssembly,
        resolverOwner: PublicSuffixResolverOwner
    ) {
        assertEquals(
            CompiledBlocklistStatus.Loaded(entryCount = ACTIVE_FIXTURE_ENTRIES),
            assembly.compiledBlocklistStatus
        )
        assertEquals(
            PublicSuffixResolverStatus.Loaded(
                exactRules = 9_950,
                wildcardRules = 281,
                exceptionRules = 8
            ),
            resolverOwner.status()
        )
        assertTrue(assembly.matcher.shouldBlock("github.com"))
        assertTrue(assembly.matcher.shouldBlock("cdn.github.com"))
        assertFalse(assembly.matcher.shouldBlock("example.com"))
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

    private data class ColdActiveMeasurement(
        val firstActiveAssemblyNanos: Long,
        val coldInclusiveHeapDeltaBytes: Long,
        val cachedAssemblySamples: LongArray,
        val exactLookupSamples: LongArray,
        val parentLookupSamples: LongArray,
        val unrelatedLookupSamples: LongArray,
        val resolverStatus: PublicSuffixResolverStatus.Loaded
    )

    private data class SteadyHeapMeasurement(
        val exactPolicySamples: LongArray,
        val parentPolicySamples: LongArray,
        val parentIncrementalSamples: LongArray
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
        val steadyHeapIterations: Int,
        val steadyExactPolicyRetainedHeapMedianBytes: Long,
        val steadyParentPolicyRetainedHeapMedianBytes: Long,
        val steadyParentIncrementalHeapMedianBytes: Long,
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
              "steady_heap_iterations": $steadyHeapIterations,
              "steady_exact_policy_retained_heap_median_bytes": $steadyExactPolicyRetainedHeapMedianBytes,
              "steady_parent_policy_retained_heap_median_bytes": $steadyParentPolicyRetainedHeapMedianBytes,
              "steady_parent_incremental_heap_median_bytes": $steadyParentIncrementalHeapMedianBytes,
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
        private const val HEAP_ITERATIONS = 5
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
