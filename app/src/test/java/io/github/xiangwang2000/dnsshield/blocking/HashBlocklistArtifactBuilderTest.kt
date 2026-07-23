package io.github.xiangwang2000.dnsshield.blocking

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class HashBlocklistArtifactBuilderTest {
    @Test
    fun buildsTheSameArtifactRegardlessOfSourceOrderAndDuplicates() {
        val first = HashBlocklistArtifactBuilder.build(
            listOf("Example.com", "ads.example", " example.com ", "", "unknown")
        )
        val second = HashBlocklistArtifactBuilder.build(
            listOf("ads.example", "EXAMPLE.COM")
        )

        assertEquals(2, first.entryCount)
        assertContentEquals(first.bytes, second.bytes)
        assertEquals(first.sha256, second.sha256)
        assertEquals(64, first.sha256.length)
    }

    @Test
    fun inspectsACanonicalArtifact() {
        val artifact = HashBlocklistArtifactBuilder.build(listOf("alpha.example", "beta.example"))

        val inspected = HashBlocklistArtifactBuilder.inspect(artifact.bytes)

        assertEquals(artifact.entryCount, inspected.entryCount)
        assertEquals(artifact.sha256, inspected.sha256)
        assertContentEquals(artifact.bytes, inspected.bytes)
    }

    @Test
    fun rejectsCorruptArtifacts() {
        val artifact = HashBlocklistArtifactBuilder.build(listOf("example.com"))
        val wrongMagic = artifact.bytes.copyOf().also { it[0] = 'X'.code.toByte() }
        val truncated = artifact.bytes.copyOf(artifact.bytes.size - 1)

        assertFailsWith<IllegalArgumentException> {
            HashBlocklistArtifactBuilder.inspect(wrongMagic)
        }
        assertFailsWith<IllegalArgumentException> {
            HashBlocklistArtifactBuilder.inspect(truncated)
        }
    }
}
