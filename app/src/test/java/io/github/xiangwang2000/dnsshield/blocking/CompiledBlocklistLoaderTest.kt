package io.github.xiangwang2000.dnsshield.blocking

import java.io.File
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

class CompiledBlocklistLoaderTest {
    @Test
    fun loadsSharedCompilerFixtureFromFile() {
        val encoded = Files.readString(findRepositoryFixture(), StandardCharsets.US_ASCII)
        val mappedFile = writePersistentTempFile(Base64.getDecoder().decode(encoded.trim()))

        val blocklist = CompiledBlocklistLoader.fromFile(mappedFile)
        val matcher = CompiledBlocklistMatcher(blocklist)

        assertEquals(4, blocklist.entryCount)
        assertTrue(matcher.shouldBlock("doubleclick.net"))
        assertTrue(matcher.shouldBlock("PAGEAD2.GOOGLESYNDICATION.COM"))
        assertTrue(matcher.shouldBlock("telemetry.example"))
        assertTrue(matcher.shouldBlock("github.com"))
        assertFalse(matcher.shouldBlock("example.com"))
    }

    @Test
    fun rejectsMissingAndEmptyFiles() {
        val missing = File(System.getProperty("java.io.tmpdir"), "dns-shield-missing-${System.nanoTime()}.bin")
        assertFailsWith<IllegalArgumentException> {
            CompiledBlocklistLoader.fromFile(missing)
        }

        val empty = writePersistentTempFile(ByteArray(0))
        assertFailsWith<IllegalArgumentException> {
            CompiledBlocklistLoader.fromFile(empty)
        }
    }

    @Test
    fun propagatesArtifactValidationFailures() {
        val invalid = writePersistentTempFile("not-a-blocklist".toByteArray(StandardCharsets.US_ASCII))
        assertFailsWith<IllegalArgumentException> {
            CompiledBlocklistLoader.fromFile(invalid)
        }
    }

    private fun writePersistentTempFile(bytes: ByteArray): File {
        val file = Files.createTempFile("dns-shield-blocklist-", ".bin").toFile()
        file.writeBytes(bytes)
        file.deleteOnExit()
        return file
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
}
