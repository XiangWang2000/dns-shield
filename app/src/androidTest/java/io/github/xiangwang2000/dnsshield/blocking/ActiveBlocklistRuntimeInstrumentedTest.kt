package io.github.xiangwang2000.dnsshield.blocking

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises the optional app-private active.bin through the production asset boundary on-device. */
@RunWith(AndroidJUnit4::class)
class ActiveBlocklistRuntimeInstrumentedTest {
    @Test
    fun activeBlocklistLifecycleUsesBuiltInAndParentAwarePolicies() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext
        val filesDirectory = targetContext.filesDir
        val activeFile = RuntimeDomainPolicy.activeBlocklistFile(filesDirectory)

        removeActiveFile(activeFile)
        try {
            var resolverProviderCalls = 0
            val missingResolverOwner = PublicSuffixResolverOwner.fromAssets(targetContext.assets)
            val missing = RuntimeDomainPolicy.assemble(
                filesDirectory = filesDirectory,
                registrableDomainResolverProvider = {
                    resolverProviderCalls++
                    missingResolverOwner.resolverOrNull()
                }
            )
            assertEquals(CompiledBlocklistStatus.NotConfigured, missing.compiledBlocklistStatus)
            assertEquals(0, resolverProviderCalls)
            assertEquals(PublicSuffixResolverStatus.NotLoaded, missingResolverOwner.status())
            assertDiagnosticContains(missing.compiledBlocklistStatus, "compiled blocklist")
            assertBuiltInPolicy(missing)

            writeFixture(activeFile)
            val resolverOwner = PublicSuffixResolverOwner.fromAssets(targetContext.assets)
            resolverProviderCalls = 0
            val loaded = RuntimeDomainPolicy.assemble(
                filesDirectory = filesDirectory,
                registrableDomainResolverProvider = {
                    resolverProviderCalls++
                    resolverOwner.resolverOrNull()
                }
            )
            assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), loaded.compiledBlocklistStatus)
            assertEquals(1, resolverProviderCalls)
            assertDiagnosticContains(loaded.compiledBlocklistStatus, "compiled blocklist")
            assertTrue(DomainPolicyDiagnostics.message(loaded.compiledBlocklistStatus).contains("4"))
            assertEquals(
                PublicSuffixResolverStatus.Loaded(
                    exactRules = 9_950,
                    wildcardRules = 281,
                    exceptionRules = 8
                ),
                resolverOwner.status()
            )
            assertTrue(loaded.matcher.shouldBlock("admob.com"))
            assertTrue(loaded.matcher.shouldBlock("github.com"))
            assertTrue(loaded.matcher.shouldBlock("cdn.github.com"))
            assertFalse(loaded.matcher.shouldBlock("example.com"))

            activeFile.writeText("not a compiled blocklist")
            resolverProviderCalls = 0
            val rejectedResolverOwner = PublicSuffixResolverOwner.fromAssets(targetContext.assets)
            val rejected = RuntimeDomainPolicy.assemble(
                filesDirectory = filesDirectory,
                registrableDomainResolverProvider = {
                    resolverProviderCalls++
                    rejectedResolverOwner.resolverOrNull()
                }
            )
            assertTrue(rejected.compiledBlocklistStatus is CompiledBlocklistStatus.Rejected)
            assertEquals(0, resolverProviderCalls)
            assertEquals(PublicSuffixResolverStatus.NotLoaded, rejectedResolverOwner.status())
            assertDiagnosticContains(rejected.compiledBlocklistStatus, "compiled blocklist")
            assertBuiltInPolicy(rejected)

            removeActiveFile(activeFile)
            resolverProviderCalls = 0
            val removedResolverOwner = PublicSuffixResolverOwner.fromAssets(targetContext.assets)
            val removed = RuntimeDomainPolicy.assemble(
                filesDirectory = filesDirectory,
                registrableDomainResolverProvider = {
                    resolverProviderCalls++
                    removedResolverOwner.resolverOrNull()
                }
            )
            assertEquals(CompiledBlocklistStatus.NotConfigured, removed.compiledBlocklistStatus)
            assertEquals(0, resolverProviderCalls)
            assertEquals(PublicSuffixResolverStatus.NotLoaded, removedResolverOwner.status())
            assertDiagnosticContains(removed.compiledBlocklistStatus, "compiled blocklist")
            assertBuiltInPolicy(removed)
        } finally {
            removeActiveFile(activeFile)
        }
    }

    private fun assertDiagnosticContains(status: CompiledBlocklistStatus, expectedText: String) {
        assertTrue(DomainPolicyDiagnostics.message(status).contains(expectedText))
    }

    private fun assertBuiltInPolicy(assembly: DomainPolicyAssembly) {
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertFalse(assembly.matcher.shouldBlock("github.com"))
        assertFalse(assembly.matcher.shouldBlock("example.com"))
    }

    private fun writeFixture(activeFile: File) {
        check(activeFile.parentFile?.mkdirs() != false)
        activeFile.writeBytes(
            Base64.getDecoder().decode(
                "RE5TSEJMMDEBAAAAAQAAAAQAAAAAAAAAWV11x9vzG2vNdXcSzQSM3HjfSXkCaJ7dZDit/w2/NO0="
            )
        )
    }

    private fun removeActiveFile(activeFile: File) {
        if (activeFile.isDirectory) {
            check(activeFile.deleteRecursively())
        } else if (activeFile.exists()) {
            check(activeFile.delete())
        }
    }
}

