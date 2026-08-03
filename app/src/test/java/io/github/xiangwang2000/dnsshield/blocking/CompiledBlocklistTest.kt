package io.github.xiangwang2000.dnsshield.blocking

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CompiledBlocklistTest {
    @Test
    fun readsHeaderAndFindsUnsignedSortedHashes() {
        val hashes = longArrayOf(0L, Long.MAX_VALUE, Long.MIN_VALUE, -1L)
        val blocklist = CompiledBlocklist.fromByteBuffer(buildArtifact(hashes))

        assertEquals(hashes.size, blocklist.entryCount)
        hashes.forEach { assertTrue(blocklist.containsHash(it)) }
        assertFalse(blocklist.containsHash(2L))
        blocklist.validateSorted()
    }

    @Test
    fun matcherUsesSameGoldenFnv1aHashesAsPythonCompiler() {
        assertEquals(0xDC8C04CD127775CDUL.toLong(), fnv1a64("doubleclick.net"))
        assertEquals(0x6B1BF3DBC7755D59UL.toLong(), fnv1a64("github.com"))

        val blocklist = CompiledBlocklist.fromByteBuffer(
            buildArtifact(longArrayOf(fnv1a64("doubleclick.net")))
        )
        val matcher = CompiledBlocklistMatcher(blocklist)

        assertTrue(matcher.shouldBlock(" DOUBLECLICK.NET "))
        assertFalse(matcher.shouldBlock("github.com"))
        assertFalse(matcher.shouldBlock("Unknown"))
    }

    @Test
    fun readsSharedPythonCompilerFixture() {
        val encodedFixture = Files.readString(findRepositoryFixture(), StandardCharsets.US_ASCII)
        val artifact = Base64.getDecoder().decode(encodedFixture.trim())
        val blocklist = CompiledBlocklist.fromByteBuffer(ByteBuffer.wrap(artifact))
        val matcher = CompiledBlocklistMatcher(blocklist)

        assertEquals(4, blocklist.entryCount)
        blocklist.validateSorted()
        assertTrue(matcher.shouldBlock("doubleclick.net"))
        assertTrue(matcher.shouldBlock("PAGEAD2.GOOGLESYNDICATION.COM"))
        assertTrue(matcher.shouldBlock("telemetry.example"))
        assertTrue(matcher.shouldBlock("github.com"))
        assertFalse(matcher.shouldBlock("example.com"))
    }

    @Test
    fun rejectsInvalidHeadersAndSizes() {
        assertFailsWith<IllegalArgumentException> {
            CompiledBlocklist.fromByteBuffer(ByteBuffer.allocate(8))
        }

        val wrongMagic = buildArtifact(longArrayOf(1L))
        wrongMagic.put(0, 'X'.code.toByte())
        assertFailsWith<IllegalArgumentException> {
            CompiledBlocklist.fromByteBuffer(wrongMagic)
        }

        val truncated = buildArtifact(longArrayOf(1L, 2L)).apply {
            limit(limit() - Long.SIZE_BYTES)
        }
        assertFailsWith<IllegalArgumentException> {
            CompiledBlocklist.fromByteBuffer(truncated)
        }

        val negativeEntryCount = ByteBuffer.allocate(HEADER_SIZE)
            .order(ByteOrder.LITTLE_ENDIAN)
            .apply {
                put(MAGIC.toByteArray(StandardCharsets.US_ASCII))
                putInt(FORMAT_VERSION)
                putInt(HASH_ALGORITHM_FNV1A_64)
                putLong(Long.MIN_VALUE / 4)
                flip()
            }
        assertFailsWith<IllegalArgumentException> {
            CompiledBlocklist.fromByteBuffer(negativeEntryCount)
        }
    }

    @Test
    fun optionalValidationRejectsDuplicateOrUnsortedHashes() {
        val duplicate = CompiledBlocklist.fromByteBuffer(buildArtifact(longArrayOf(1L, 1L)))
        assertFailsWith<IllegalArgumentException> { duplicate.validateSorted() }

        val unsortedUnsigned = CompiledBlocklist.fromByteBuffer(
            buildArtifact(longArrayOf(Long.MIN_VALUE, Long.MAX_VALUE))
        )
        assertFailsWith<IllegalArgumentException> { unsortedUnsigned.validateSorted() }
    }

    private fun findRepositoryFixture(): Path {
        val relative = Paths.get("tools", "tests", "fixtures", "blocklist.bin.base64")
        var directory: Path? = Paths.get(System.getProperty("user.dir")).toAbsolutePath()
        repeat(4) {
            val current = directory ?: return@repeat
            val candidate = current.resolve(relative)
            if (Files.isRegularFile(candidate)) return candidate
            directory = current.parent
        }
        error("Unable to locate repository fixture: $relative")
    }

    private fun buildArtifact(hashes: LongArray): ByteBuffer {
        return ByteBuffer.allocate(HEADER_SIZE + hashes.size * Long.SIZE_BYTES)
            .order(ByteOrder.LITTLE_ENDIAN)
            .apply {
                put(MAGIC.toByteArray(StandardCharsets.US_ASCII))
                putInt(FORMAT_VERSION)
                putInt(HASH_ALGORITHM_FNV1A_64)
                putLong(hashes.size.toLong())
                hashes.forEach(::putLong)
                flip()
            }
    }

    private companion object {
        const val MAGIC = "DNSHBL01"
        const val FORMAT_VERSION = 1
        const val HASH_ALGORITHM_FNV1A_64 = 1
        const val HEADER_SIZE = 24
    }
}
