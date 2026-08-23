package io.github.xiangwang2000.dnsshield.blocking

import android.os.Build
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

/** Compares the built-in-only policy with the packaged production active.bin on one device. */
@RunWith(AndroidJUnit4::class)
class ProductionBlocklistInstrumentedBenchmarkTest {
    @Test
    fun benchmarkProductionBlocklist() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val activeFile = RuntimeDomainPolicy.activeBlocklistFile(context.filesDir)
        val previous = activeFile.takeIf { it.isFile }?.readBytes()
        if (activeFile.exists()) check(activeFile.deleteRecursively())

        try {
            val builtInAssemblySamples = LongArray(ASSEMBLY_ITERATIONS) {
                measureNanos {
                    benchmarkSink = RuntimeDomainPolicy.assemble(context.filesDir)
                }
            }
            val builtInAssembly = benchmarkSink as DomainPolicyAssembly
            assertEquals(
                CompiledBlocklistStatus.NotConfigured,
                builtInAssembly.compiledBlocklistStatus
            )
            assertFalse(builtInAssembly.matcher.shouldBlock(BLOCKED_ONLY_BY_PRODUCTION))

            val loader = ProductionBlocklistAssetLoader.fromAssets(context.assets)
            val resolverOwner = PublicSuffixResolverOwner.fromAssets(context.assets)
            var firstAssembly: DomainPolicyAssembly? = null
            val firstProductionAssemblyNanos = measureNanos {
                firstAssembly = RuntimeDomainPolicy.assemble(
                    filesDirectory = context.filesDir,
                    loadBundledBlocklist = loader::load,
                    registrableDomainResolverProvider = resolverOwner::resolverOrNull
                )
            }
            val productionAssembly = checkNotNull(firstAssembly)
            assertProductionPolicy(productionAssembly)

            val cachedProductionAssemblySamples = LongArray(ASSEMBLY_ITERATIONS) {
                measureNanos {
                    benchmarkSink = RuntimeDomainPolicy.assemble(
                        filesDirectory = context.filesDir,
                        loadBundledBlocklist = loader::load,
                        registrableDomainResolverProvider = resolverOwner::resolverOrNull
                    )
                }
            }
            benchmarkSink = productionAssembly

            val builtInLookupSamples = benchmarkLookups(
                builtInAssembly,
                BLOCKED_ONLY_BY_PRODUCTION,
                expectedBlocked = false
            )
            val productionExactLookupSamples = benchmarkLookups(
                productionAssembly,
                BLOCKED_ONLY_BY_PRODUCTION,
                expectedBlocked = true
            )
            val productionParentLookupSamples = benchmarkLookups(
                productionAssembly,
                "sub.$BLOCKED_ONLY_BY_PRODUCTION",
                expectedBlocked = true
            )
            val productionAllowedLookupSamples = benchmarkLookups(
                productionAssembly,
                ALLOWED_DOMAIN,
                expectedBlocked = false
            )

            val report = Report(
                model = Build.MODEL ?: "unknown",
                androidRelease = Build.VERSION.RELEASE ?: "unknown",
                apiLevel = Build.VERSION.SDK_INT,
                abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown",
                artifactBytes = ProductionBlocklistArtifact.contract.artifactSize,
                entryCount = ProductionBlocklistArtifact.contract.entryCount,
                assemblyIterations = ASSEMBLY_ITERATIONS,
                builtInAssemblyMedianNanos = percentile(builtInAssemblySamples, 0.50),
                builtInAssemblyP95Nanos = percentile(builtInAssemblySamples, 0.95),
                firstProductionAssemblyNanos = firstProductionAssemblyNanos,
                cachedProductionAssemblyMedianNanos =
                    percentile(cachedProductionAssemblySamples, 0.50),
                cachedProductionAssemblyP95Nanos =
                    percentile(cachedProductionAssemblySamples, 0.95),
                lookupBatches = LOOKUP_BATCHES,
                lookupsPerBatch = LOOKUPS_PER_BATCH,
                builtInLookupMedianNanos = percentile(builtInLookupSamples, 0.50),
                builtInLookupP95Nanos = percentile(builtInLookupSamples, 0.95),
                productionExactLookupMedianNanos =
                    percentile(productionExactLookupSamples, 0.50),
                productionExactLookupP95Nanos =
                    percentile(productionExactLookupSamples, 0.95),
                productionParentLookupMedianNanos =
                    percentile(productionParentLookupSamples, 0.50),
                productionParentLookupP95Nanos =
                    percentile(productionParentLookupSamples, 0.95),
                productionAllowedLookupMedianNanos =
                    percentile(productionAllowedLookupSamples, 0.50),
                productionAllowedLookupP95Nanos =
                    percentile(productionAllowedLookupSamples, 0.95)
            )

            val reportDirectory = checkNotNull(context.getExternalFilesDir(null))
            val reportFile = File(reportDirectory, REPORT_FILE_NAME)
            writeReport(reportFile, report.toJson())
            println("DNS_SHIELD_PRODUCTION_BLOCKLIST_REPORT=${reportFile.absolutePath}")
            println(report.toJson())
        } finally {
            benchmarkSink = null
            if (activeFile.exists()) check(activeFile.deleteRecursively())
            if (previous != null) {
                val parent = checkNotNull(activeFile.parentFile)
                check(parent.mkdirs() || parent.isDirectory)
                activeFile.writeBytes(previous)
            }
        }
    }

    private fun assertProductionPolicy(assembly: DomainPolicyAssembly) {
        assertEquals(
            CompiledBlocklistStatus.Loaded(
                ProductionBlocklistArtifact.contract.entryCount
            ),
            assembly.compiledBlocklistStatus
        )
        assertTrue(assembly.matcher.shouldBlock(BLOCKED_ONLY_BY_PRODUCTION))
        assertTrue(assembly.matcher.shouldBlock("sub.$BLOCKED_ONLY_BY_PRODUCTION"))
        assertFalse(assembly.matcher.shouldBlock(ALLOWED_DOMAIN))
    }

    private fun benchmarkLookups(
        assembly: DomainPolicyAssembly,
        domain: String,
        expectedBlocked: Boolean
    ): LongArray {
        assertEquals(expectedBlocked, assembly.matcher.shouldBlock(domain))
        var checksum = 0
        repeat(WARMUP_BATCHES) {
            repeat(LOOKUPS_PER_BATCH) {
                if (assembly.matcher.shouldBlock(domain)) checksum = checksum xor domain.hashCode()
            }
        }
        val samples = LongArray(LOOKUP_BATCHES) {
            measureNanos {
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

    private fun percentile(values: LongArray, percentile: Double): Long {
        val sorted = values.sortedArray()
        val index = (ceil(percentile * sorted.size).toInt() - 1).coerceIn(sorted.indices)
        return sorted[index]
    }

    private fun writeReport(file: File, contents: String) {
        file.parentFile?.mkdirs()
        val temporary = File(file.parentFile, file.name + ".tmp")
        temporary.writeText(contents, Charsets.UTF_8)
        if (file.exists()) check(file.delete())
        check(temporary.renameTo(file))
    }

    private data class Report(
        val model: String,
        val androidRelease: String,
        val apiLevel: Int,
        val abi: String,
        val artifactBytes: Int,
        val entryCount: Int,
        val assemblyIterations: Int,
        val builtInAssemblyMedianNanos: Long,
        val builtInAssemblyP95Nanos: Long,
        val firstProductionAssemblyNanos: Long,
        val cachedProductionAssemblyMedianNanos: Long,
        val cachedProductionAssemblyP95Nanos: Long,
        val lookupBatches: Int,
        val lookupsPerBatch: Int,
        val builtInLookupMedianNanos: Long,
        val builtInLookupP95Nanos: Long,
        val productionExactLookupMedianNanos: Long,
        val productionExactLookupP95Nanos: Long,
        val productionParentLookupMedianNanos: Long,
        val productionParentLookupP95Nanos: Long,
        val productionAllowedLookupMedianNanos: Long,
        val productionAllowedLookupP95Nanos: Long
    ) {
        fun toJson(): String = buildString {
            append("{\n")
            append("  \"model\": \"").append(escapeJson(model)).append("\",\n")
            append("  \"android_release\": \"").append(escapeJson(androidRelease)).append("\",\n")
            append("  \"api_level\": ").append(apiLevel).append(",\n")
            append("  \"abi\": \"").append(escapeJson(abi)).append("\",\n")
            append("  \"artifact_bytes\": ").append(artifactBytes).append(",\n")
            append("  \"entry_count\": ").append(entryCount).append(",\n")
            append("  \"assembly_iterations\": ").append(assemblyIterations).append(",\n")
            append("  \"built_in_assembly_median_nanos\": ").append(builtInAssemblyMedianNanos).append(",\n")
            append("  \"built_in_assembly_p95_nanos\": ").append(builtInAssemblyP95Nanos).append(",\n")
            append("  \"first_production_assembly_nanos\": ").append(firstProductionAssemblyNanos).append(",\n")
            append("  \"cached_production_assembly_median_nanos\": ").append(cachedProductionAssemblyMedianNanos).append(",\n")
            append("  \"cached_production_assembly_p95_nanos\": ").append(cachedProductionAssemblyP95Nanos).append(",\n")
            append("  \"lookup_batches\": ").append(lookupBatches).append(",\n")
            append("  \"lookups_per_batch\": ").append(lookupsPerBatch).append(",\n")
            append("  \"built_in_lookup_median_nanos\": ").append(builtInLookupMedianNanos).append(",\n")
            append("  \"built_in_lookup_p95_nanos\": ").append(builtInLookupP95Nanos).append(",\n")
            append("  \"production_exact_lookup_median_nanos\": ").append(productionExactLookupMedianNanos).append(",\n")
            append("  \"production_exact_lookup_p95_nanos\": ").append(productionExactLookupP95Nanos).append(",\n")
            append("  \"production_parent_lookup_median_nanos\": ").append(productionParentLookupMedianNanos).append(",\n")
            append("  \"production_parent_lookup_p95_nanos\": ").append(productionParentLookupP95Nanos).append(",\n")
            append("  \"production_allowed_lookup_median_nanos\": ").append(productionAllowedLookupMedianNanos).append(",\n")
            append("  \"production_allowed_lookup_p95_nanos\": ").append(productionAllowedLookupP95Nanos).append("\n")
            append("}")
        }
    }

    private companion object {
        const val REPORT_FILE_NAME = "production-blocklist.android-benchmark.json"
        const val BLOCKED_ONLY_BY_PRODUCTION = "app-measurement.com"
        const val ALLOWED_DOMAIN = "github.com"
        const val ASSEMBLY_ITERATIONS = 100
        const val WARMUP_BATCHES = 10
        const val LOOKUP_BATCHES = 30
        const val LOOKUPS_PER_BATCH = 1_000

        @Volatile
        var benchmarkSink: Any? = null

        @Volatile
        var benchmarkChecksum = 0

        fun measureNanos(block: () -> Unit): Long {
            val started = System.nanoTime()
            block()
            return max(0L, System.nanoTime() - started)
        }

        fun escapeJson(value: String): String = buildString {
            for (character in value) {
                when (character) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(character)
                }
            }
        }
    }
}
