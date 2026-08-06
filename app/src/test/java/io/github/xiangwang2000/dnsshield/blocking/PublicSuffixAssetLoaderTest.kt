package io.github.xiangwang2000.dnsshield.blocking

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

        assertEquals(153_740, contract.artifactSize)
        assertEquals(
            "401b3ed16ed28eb9a8362a93f8f054462fa16bdce26a0e7eaa6c5a3cb5a6eb70",
            contract.artifactSha256
        )
        assertEquals(
            "72d07fea544b74d920be2394d4c5fbb38dd3f5f3ccac299e27809009bac1c550",
            contract.normalizedSourceSha256
        )
        assertEquals(9_950, contract.exactRules)
        assertEquals(281, contract.wildcardRules)
        assertEquals(8, contract.exceptionRules)
    }

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
