package io.github.xiangwang2000.dnsshield.blocking

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

class PublicSuffixAssetLoaderTest {
    @Test
    fun validatesFixtureAndCachesOneResolver() {
        val reads = AtomicInteger()
        val loader = PublicSuffixAssetLoader(
            readArtifact = {
                reads.incrementAndGet()
                fixtureArtifact.clone()
            },
            contract = fixtureContract
        )

        val first = loader.load()
        val second = loader.load()

        assertSame(first, second)
        assertEquals(1, reads.get())
        assertEquals("example.co.uk", first.registrableDomain("a.example.co.uk"))
        assertEquals("tenant.github.io", first.registrableDomain("ads.tenant.github.io"))
    }

    @Test
    fun concurrentCallersShareOneReadAndResolver() {
        val reads = AtomicInteger()
        val loader = PublicSuffixAssetLoader(
            readArtifact = {
                reads.incrementAndGet()
                Thread.sleep(20)
                fixtureArtifact.clone()
            },
            contract = fixtureContract
        )
        val executor = Executors.newFixedThreadPool(8)

        try {
            val futures = executor.invokeAll(
                List(16) { Callable { loader.load() } }
            )
            val resolvers = futures.map { it.get(5, TimeUnit.SECONDS) }

            assertEquals(1, reads.get())
            resolvers.forEach { resolver -> assertSame(resolvers.first(), resolver) }
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun rejectsTamperedArtifactBeforeCaching() {
        val reads = AtomicInteger()
        val tampered = fixtureArtifact.clone().apply {
            this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
        }
        val loader = PublicSuffixAssetLoader(
            readArtifact = {
                reads.incrementAndGet()
                tampered.clone()
            },
            contract = fixtureContract
        )

        assertFailsWith<IllegalArgumentException> { loader.load() }
        assertFailsWith<IllegalArgumentException> { loader.load() }
        assertEquals(2, reads.get())
    }

    @Test
    fun rejectsMetadataContractDrift() {
        val wrongCounts = fixtureContract.copy(exactRules = fixtureContract.exactRules + 1)
        val loader = PublicSuffixAssetLoader(
            readArtifact = { fixtureArtifact.clone() },
            contract = wrongCounts
        )

        assertFailsWith<IllegalArgumentException> { loader.load() }
    }

    @Test
    fun productionContractMatchesReviewedManifest() {
        val contract = ProductionPublicSuffixArtifact.contract
        val manifest = Files.readString(findProductionManifest())

        assertEquals(jsonInt(manifest, "artifact_size"), contract.artifactSize)
        assertEquals(jsonString(manifest, "artifact_sha256"), contract.artifactSha256)
        assertEquals(
            jsonString(manifest, "normalized_sha256"),
            contract.normalizedSourceSha256
        )
        assertEquals(jsonInt(manifest, "exact_rules"), contract.exactRules)
        assertEquals(jsonInt(manifest, "wildcard_rules"), contract.wildcardRules)
        assertEquals(jsonInt(manifest, "exception_rules"), contract.exceptionRules)
    }

    private fun findProductionManifest(): Path =
        generateSequence(Paths.get("").toAbsolutePath().normalize()) { current ->
            current.parent
        }
            .map { root -> root.resolve("tools/public_suffix_production.json") }
            .firstOrNull { candidate -> Files.isRegularFile(candidate) }
            ?: error("Unable to locate tools/public_suffix_production.json")

    private fun jsonString(document: String, key: String): String =
        Regex("\"${Regex.escape(key)}\"\\s*:\\s*\"([^\"]+)\"")
            .find(document)
            ?.groupValues
            ?.get(1)
            ?: error("Missing JSON string field: $key")

    private fun jsonInt(document: String, key: String): Int =
        Regex("\"${Regex.escape(key)}\"\\s*:\\s*(\\d+)")
            .find(document)
            ?.groupValues
            ?.get(1)
            ?.toInt()
            ?: error("Missing JSON integer field: $key")

    private val fixtureArtifact: ByteArray
        get() = Base64.getDecoder().decode(
            "RE5TSFBTMDEBAAAAAQAAAAkAAAACAAAAAgAAAHPsytv9BqHn5cpMuwAfzbOdZfBHZliCgeL6TGd89acrDABibG9nc3BvdC5jb20CAGNrBQBjby51awMAY29tCQBnaXRodWIuaW8CAGlvAgBqcAMAb3JnAgB1awIAY2sLAGthd2FzYWtpLmpwEABjaXR5Lmthd2FzYWtpLmpwBgB3d3cuY2s="
        )

    private val fixtureContract: PublicSuffixArtifactContract
        get() {
            val artifact = fixtureArtifact
            return PublicSuffixArtifactContract(
                artifactSize = artifact.size,
                artifactSha256 = MessageDigest.getInstance("SHA-256")
                    .digest(artifact)
                    .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xFF) },
                normalizedSourceSha256 =
                    "73eccadbfd06a1e7e5ca4cbb001fcdb39d65f04766588281e2fa4c677cf5a72b",
                exactRules = 9,
                wildcardRules = 2,
                exceptionRules = 2
            )
        }
}
