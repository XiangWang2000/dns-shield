package io.github.xiangwang2000.dnsshield.blocking

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProductionBlocklistAssetInstrumentedTest {
    @Test
    fun malformedPrivateOverrideFallsBackToPackagedBlocklistAndReportsStatus() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.cacheDir, "blocklist-fallback-${System.nanoTime()}")
        assertTrue(directory.mkdirs())
        val activeFile = RuntimeDomainPolicy.activeBlocklistFile(directory)
        val loader = ProductionBlocklistAssetLoader.fromAssets(context.assets)

        try {
            assertTrue(activeFile.parentFile!!.mkdirs())
            activeFile.writeText("invalid override")
            val assembly = RuntimeDomainPolicy.assemble(
                filesDirectory = directory,
                loadBundledBlocklist = loader::load,
                bundledSourceMetadata = loader.sourceMetadata
            )

            assertEquals(RuleBlocklistSource.APK_BUNDLED, assembly.displayStatus.source)
            assertEquals(RuleBlocklistValidation.APK_VERIFIED, assembly.displayStatus.validation)
            assertEquals(247_497, assembly.displayStatus.entryCount)
            assertEquals(loader.sourceMetadata.revision, assembly.displayStatus.sourceRevision)
            assertNotNull(assembly.displayStatus.degradationReason)
            assertTrue(assembly.matcher.shouldBlock("app-measurement.com"))
            assertFalse(assembly.matcher.shouldBlock("github.com"))
        } finally {
            check(directory.deleteRecursively())
        }
    }

    @Test
    fun packagedBlocklistLoadsThroughProductionRuntimePolicy() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val activeFile = RuntimeDomainPolicy.activeBlocklistFile(context.filesDir)
        val previous = activeFile.takeIf { it.isFile }?.readBytes()
        if (activeFile.exists()) {
            check(activeFile.deleteRecursively())
        }

        try {
            val blocklistLoader = ProductionBlocklistAssetLoader.fromAssets(context.assets)
            val resolverOwner = PublicSuffixResolverOwner.fromAssets(context.assets)
            val assembly = RuntimeDomainPolicy.assemble(
                filesDirectory = context.filesDir,
                loadBundledBlocklist = blocklistLoader::load,
                registrableDomainResolverProvider = resolverOwner::resolverOrNull
            )

            assertEquals(
                CompiledBlocklistStatus.Loaded(entryCount = 247_497),
                assembly.compiledBlocklistStatus
            )
            assertTrue(assembly.matcher.shouldBlock("app-measurement.com"))
            assertTrue(assembly.matcher.shouldBlock("sub.app-measurement.com"))
            assertTrue(assembly.matcher.shouldBlock("supportmetrics.apple.com"))
            assertFalse(assembly.matcher.shouldBlock("github.com"))
        } finally {
            if (activeFile.exists()) {
                check(activeFile.deleteRecursively())
            }
            if (previous != null) {
                check(activeFile.parentFile?.mkdirs() == true || activeFile.parentFile?.isDirectory == true)
                activeFile.writeBytes(previous)
            }
        }
    }
}
