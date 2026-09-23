package io.github.xiangwang2000.dnsshield.blocking

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Uses real packaged assets and a disposable directory in the isolated D12 application. */
@RunWith(AndroidJUnit4::class)
class RulePolicyStatusInstrumentedTest {
    @Test
    fun activeSourceAndFallbackMatchEffectivePolicy() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("io.github.xiangwang2000.dnsshield.d12test", context.packageName)
        val directory = File(context.cacheDir, "d12-policy-status-${System.nanoTime()}")
        assertTrue(directory.mkdirs())
        val active = RuntimeDomainPolicy.activeBlocklistFile(directory)
        val loader = ProductionBlocklistAssetLoader.fromAssets(context.assets)
        fun assemble(failBundled: Boolean = false): DomainPolicyAssembly = RuntimeDomainPolicy.assemble(
            filesDirectory = directory,
            loadBundledBlocklist = { if (failBundled) error("fixture bundled failure") else loader.load() },
            bundledSourceMetadata = loader.sourceMetadata
        )
        try {
            val bundled = assemble()
            assertEquals(RuleBlocklistSource.APK_BUNDLED, bundled.displayStatus.source)
            assertEquals(RuleBlocklistValidation.APK_VERIFIED, bundled.displayStatus.validation)
            assertEquals(102972, bundled.displayStatus.entryCount)
            assertEquals(loader.sourceMetadata.revision, bundled.displayStatus.sourceRevision)
            assertTrue(bundled.matcher.shouldBlock("app-measurement.com"))
            assertFalse(bundled.matcher.shouldBlock("github.com"))

            assertTrue(active.parentFile!!.mkdirs())
            active.writeBytes(context.assets.open("active.bin").use { it.readBytes() })
            val private = assemble()
            assertEquals(RuleBlocklistSource.PRIVATE_OVERRIDE, private.displayStatus.source)
            assertEquals(RuleBlocklistValidation.PRIVATE_STRUCTURE_CHECKED, private.displayStatus.validation)
            assertNull(private.displayStatus.sourceRevision)
            assertTrue(private.matcher.shouldBlock("app-measurement.com"))

            active.writeText("invalid override")
            val fallback = assemble()
            assertEquals(RuleBlocklistSource.APK_BUNDLED, fallback.displayStatus.source)
            assertNotNull(fallback.displayStatus.degradationReason)
            assertTrue(fallback.matcher.shouldBlock("app-measurement.com"))
            assertEquals("invalid override", active.readText())

            val builtIn = assemble(failBundled = true)
            assertEquals(RuleBlocklistSource.BUILT_IN, builtIn.displayStatus.source)
            assertTrue(builtIn.displayStatus.degradationReason!!.contains("fixture bundled failure"))
            assertTrue(builtIn.matcher.shouldBlock("admob.com"))
            assertFalse(builtIn.matcher.shouldBlock("github.com"))
            assertEquals("invalid override", active.readText())
        } finally {
            assertTrue(directory.deleteRecursively())
        }
    }
}
