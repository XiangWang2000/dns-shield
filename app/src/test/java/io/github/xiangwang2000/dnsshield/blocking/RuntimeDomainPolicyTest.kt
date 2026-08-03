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

class RuntimeDomainPolicyTest {
    @Test
    fun usesStableAppPrivateBlocklistPath() {
        val filesDirectory = File("app-files")

        assertEquals(
            File(File(filesDirectory, "blocklists"), "active.bin"),
            RuntimeDomainPolicy.activeBlocklistFile(filesDirectory)
        )
    }

    @Test
    fun missingActiveFileIsNotConfiguredAndDoesNotCallLoader() {
        val filesDirectory = createFilesDirectory()
        var loaderCalled = false

        val assembly = RuntimeDomainPolicy.assemble(
            filesDirectory = filesDirectory,
            loadCompiledBlocklist = {
                loaderCalled = true
                error("Loader must not run for a missing active file")
            }
        )

        assertEquals(CompiledBlocklistStatus.NotConfigured, assembly.compiledBlocklistStatus)
        assertFalse(loaderCalled)
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertFalse(assembly.matcher.shouldBlock("github.com"))
    }

    @Test
    fun loadsSharedFixtureFromActivePath() {
        val filesDirectory = createFilesDirectory()
        writeSharedFixture(RuntimeDomainPolicy.activeBlocklistFile(filesDirectory))

        val assembly = RuntimeDomainPolicy.assemble(filesDirectory)

        assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), assembly.compiledBlocklistStatus)
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertTrue(assembly.matcher.shouldBlock("github.com"))
        assertFalse(assembly.matcher.shouldBlock("example.com"))
    }

    @Test
    fun malformedActiveFileIsRejectedWithoutDisablingBuiltInProtection() {
        val filesDirectory = createFilesDirectory()
        val activeFile = RuntimeDomainPolicy.activeBlocklistFile(filesDirectory)
        prepareParentDirectory(activeFile)
        activeFile.writeText("not a compiled blocklist")
        activeFile.deleteOnExit()

        val assembly = RuntimeDomainPolicy.assemble(filesDirectory)

        assertIs<CompiledBlocklistStatus.Rejected>(assembly.compiledBlocklistStatus)
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertFalse(assembly.matcher.shouldBlock("github.com"))
    }

    @Test
    fun existingDirectoryAtActivePathIsRejectedInsteadOfHidden() {
        val filesDirectory = createFilesDirectory()
        val activePath = RuntimeDomainPolicy.activeBlocklistFile(filesDirectory)
        prepareParentDirectory(activePath)
        assertTrue(activePath.mkdir())
        activePath.deleteOnExit()

        val assembly = RuntimeDomainPolicy.assemble(filesDirectory)

        assertIs<CompiledBlocklistStatus.Rejected>(assembly.compiledBlocklistStatus)
        assertTrue(assembly.matcher.shouldBlock("doubleclick.net"))
    }

    private fun createFilesDirectory(): File =
        Files.createTempDirectory("dns-shield-files-").toFile().apply { deleteOnExit() }

    private fun writeSharedFixture(destination: File) {
        val encoded = Files.readString(findRepositoryFixture(), StandardCharsets.US_ASCII)
        prepareParentDirectory(destination)
        destination.writeBytes(Base64.getDecoder().decode(encoded.trim()))
        destination.deleteOnExit()
    }

    private fun prepareParentDirectory(file: File) {
        val parent = requireNotNull(file.parentFile)
        check(parent.mkdirs() || parent.isDirectory)
        parent.deleteOnExit()
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
