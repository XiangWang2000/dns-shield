package io.github.xiangwang2000.dnsshield.blocking

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ProductionBlocklistAssetLoaderTest {
    @Test
    fun verifiesAndCachesPackagedProductionArtifact() {
        val artifact = Files.readAllBytes(productionAssetPath())
        var reads = 0
        val loader = ProductionBlocklistAssetLoader(
            readArtifact = {
                reads++
                artifact
            }
        )

        val first = loader.load()
        val second = loader.load()
        val matcher = CompiledBlocklistMatcher(first)

        assertSame(first, second)
        assertEquals(1, reads)
        assertEquals(102_972, first.entryCount)
        assertTrue(matcher.shouldBlock("doubleclick.net"))
        assertTrue(matcher.shouldBlock("app-measurement.com"))
        listOf(
            "google.com",
            "youtube.com",
            "github.com",
            "microsoft.com",
            "apple.com",
            "asus.com",
            "line.me",
            "shopee.tw",
            "pchome.com.tw",
            "momo.com.tw",
            "esunbank.com",
            "cathaybk.com.tw",
            "gov.tw"
        ).forEach { domain ->
            assertFalse(matcher.shouldBlock(domain), "Critical domain must remain allowed: $domain")
        }
    }

    @Test
    fun rejectsArtifactThatDoesNotMatchContract() {
        val artifact = Files.readAllBytes(productionAssetPath()).also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        val loader = ProductionBlocklistAssetLoader(readArtifact = { artifact })

        assertFailsWith<IllegalArgumentException> {
            loader.load()
        }
    }

    @Test
    fun verifiesTestContractWithoutProductionConstants() {
        val artifact = Files.readAllBytes(productionAssetPath())
        val contract = ProductionBlocklistArtifactContract(
            artifactSize = artifact.size,
            artifactSha256 = MessageDigest.getInstance("SHA-256")
                .digest(artifact)
                .toArtifactHexString(),
            entryCount = 102_972
        )

        assertEquals(
            102_972,
            ProductionBlocklistArtifact.verify(artifact, contract).entryCount
        )
    }

    @Test
    fun pinsDisplayedSourceMetadataToProductionManifest() {
        val contract = ProductionBlocklistArtifact.contract
        val manifest = Files.readString(productionManifestPath())

        assertEquals("badmojr/1Hosts Lite", contract.sourceName)
        assertEquals("273a6bcdcc3585bc47f1ebb6823db05ec5b7b409", contract.sourceRevision)
        assertEquals("2026-08-23", contract.sourceDate)
        assertTrue(manifest.contains("\"source_name\": \"${contract.sourceName}\""))
        assertTrue(manifest.contains("\"source_revision\": \"${contract.sourceRevision}\""))
        assertTrue(manifest.contains("\"source_date\": \"${contract.sourceDate}\""))
    }

    private fun productionAssetPath(): Path {
        val relative = Paths.get(
            "app",
            "src",
            "main",
            "assets",
            ProductionBlocklistAssetLoader.ASSET_NAME
        )
        var directory: Path? = Paths.get(System.getProperty("user.dir")).toAbsolutePath()
        repeat(4) {
            val current = directory ?: return@repeat
            val candidate = current.resolve(relative)
            if (Files.isRegularFile(candidate)) return candidate
            directory = current.parent
        }
        error("Unable to locate production blocklist asset: $relative")
    }

    private fun productionManifestPath(): Path {
        var directory: Path? = productionAssetPath().toAbsolutePath()
        repeat(5) { directory = directory?.parent }
        val repositoryRoot = directory ?: error("Unable to locate repository root")
        return repositoryRoot.resolve(Paths.get("tools", "active_blocklist_production.json"))
    }
}
