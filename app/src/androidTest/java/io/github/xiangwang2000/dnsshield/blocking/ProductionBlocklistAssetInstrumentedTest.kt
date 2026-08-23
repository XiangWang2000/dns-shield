package io.github.xiangwang2000.dnsshield.blocking

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProductionBlocklistAssetInstrumentedTest {
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
                CompiledBlocklistStatus.Loaded(entryCount = 102_972),
                assembly.compiledBlocklistStatus
            )
            assertTrue(assembly.matcher.shouldBlock("app-measurement.com"))
            assertTrue(assembly.matcher.shouldBlock("sub.app-measurement.com"))
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
