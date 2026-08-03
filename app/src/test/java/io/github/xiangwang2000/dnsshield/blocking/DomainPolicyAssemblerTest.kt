package io.github.xiangwang2000.dnsshield.blocking

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DomainPolicyAssemblerTest {
    @Test
    fun keepsBuiltInProtectionWhenCompiledBlocklistIsNotConfigured() {
        val assembly = DomainPolicyAssembler.assemble()

        assertEquals(CompiledBlocklistStatus.NotConfigured, assembly.compiledBlocklistStatus)
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertFalse(assembly.matcher.shouldBlock("github.com"))
    }

    @Test
    fun addsValidatedCompiledBlocklistAfterBuiltInMatcher() {
        val assembly = DomainPolicyAssembler.assemble(
            compiledBlocklistFile = writeSharedFixtureToTemporaryFile()
        )

        assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), assembly.compiledBlocklistStatus)
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertTrue(assembly.matcher.shouldBlock("github.com"))
        assertFalse(assembly.matcher.shouldBlock("example.com"))
    }

    @Test
    fun allowlistOverridesBothBuiltInAndCompiledMatchers() {
        val assembly = DomainPolicyAssembler.assemble(
            compiledBlocklistFile = writeSharedFixtureToTemporaryFile(),
            allowlist = ExactDomainAllowlist(listOf("admob.com", "github.com"))
        )

        assertFalse(assembly.matcher.shouldBlock("ADMOB.COM"))
        assertFalse(assembly.matcher.shouldBlock(" github.com "))
        assertTrue(assembly.matcher.shouldBlock("doubleclick.net"))
    }

    @Test
    fun rejectsMalformedFileAndFallsBackToBuiltInMatcher() {
        val malformedFile = File.createTempFile("dns-shield-malformed-", ".bin").apply {
            writeText("not a compiled blocklist")
            deleteOnExit()
        }

        val assembly = DomainPolicyAssembler.assemble(
            compiledBlocklistFile = malformedFile
        )

        val rejected = assertIs<CompiledBlocklistStatus.Rejected>(
            assembly.compiledBlocklistStatus
        )
        assertTrue(rejected.reason.isNotBlank())
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertFalse(assembly.matcher.shouldBlock("github.com"))
    }

    @Test
    fun reportsInjectedLoaderFailureWithoutDisablingBuiltInMatcher() {
        val assembly = DomainPolicyAssembler.assemble(
            compiledBlocklistFile = File("unused.bin"),
            loadCompiledBlocklist = { throw IllegalStateException("synthetic loader failure") }
        )

        assertEquals(
            CompiledBlocklistStatus.Rejected("synthetic loader failure"),
            assembly.compiledBlocklistStatus
        )
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
    }

    private fun writeSharedFixtureToTemporaryFile(): File {
        val encoded = Files.readString(findRepositoryFixture(), StandardCharsets.US_ASCII)
        return File.createTempFile("dns-shield-blocklist-", ".bin").apply {
            writeBytes(Base64.getDecoder().decode(encoded.trim()))
            deleteOnExit()
        }
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
