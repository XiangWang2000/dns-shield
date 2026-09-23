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
import kotlin.test.assertNull
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
    fun missingActiveFileIsNotConfiguredAndDoesNotCallLoaderOrResolver() {
        val filesDirectory = createFilesDirectory()
        var loaderCalled = false
        var resolverProviderCalled = false

        val assembly = RuntimeDomainPolicy.assemble(
            filesDirectory = filesDirectory,
            loadCompiledBlocklist = {
                loaderCalled = true
                error("Loader must not run for a missing active file")
            },
            registrableDomainResolverProvider = {
                resolverProviderCalled = true
                error("Resolver must not load for a missing active file")
            }
        )

        assertEquals(CompiledBlocklistStatus.NotConfigured, assembly.compiledBlocklistStatus)
        assertFalse(loaderCalled)
        assertFalse(resolverProviderCalled)
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertFalse(assembly.matcher.shouldBlock("github.com"))
    }

    @Test
    fun missingPrivateFileUsesBundledBlocklistProvider() {
        val filesDirectory = createFilesDirectory()
        var bundledProviderCalls = 0

        val assembly = RuntimeDomainPolicy.assemble(
            filesDirectory = filesDirectory,
            loadBundledBlocklist = {
                bundledProviderCalls++
                loadSharedFixture()
            }
        )

        assertEquals(1, bundledProviderCalls)
        assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), assembly.compiledBlocklistStatus)
        assertEquals(RuleBlocklistSource.APK_BUNDLED, assembly.displayStatus.source)
        assertEquals(RuleBlocklistValidation.APK_VERIFIED, assembly.displayStatus.validation)
        assertTrue(assembly.matcher.shouldBlock("github.com"))
    }

    @Test
    fun privateActiveFileTakesPrecedenceOverBundledProvider() {
        val filesDirectory = createFilesDirectory()
        writeSharedFixture(RuntimeDomainPolicy.activeBlocklistFile(filesDirectory))

        val assembly = RuntimeDomainPolicy.assemble(
            filesDirectory = filesDirectory,
            loadBundledBlocklist = {
                error("Bundled provider must not run when private active.bin exists")
            }
        )

        assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), assembly.compiledBlocklistStatus)
        assertTrue(assembly.matcher.shouldBlock("github.com"))
    }

    @Test
    fun loadsSharedFixtureFromActivePath() {
        val filesDirectory = createFilesDirectory()
        writeSharedFixture(RuntimeDomainPolicy.activeBlocklistFile(filesDirectory))

        val assembly = RuntimeDomainPolicy.assemble(filesDirectory)

        assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), assembly.compiledBlocklistStatus)
        assertEquals(RuleBlocklistSource.PRIVATE_OVERRIDE, assembly.displayStatus.source)
        assertEquals(RuleBlocklistValidation.PRIVATE_STRUCTURE_CHECKED, assembly.displayStatus.validation)
        assertNull(assembly.displayStatus.sourceRevision)
        assertNull(assembly.displayStatus.sourceDate)
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertTrue(assembly.matcher.shouldBlock("github.com"))
        assertFalse(assembly.matcher.shouldBlock("example.com"))
    }

    @Test
    fun forwardsLazyResolverOnlyForValidatedActiveBlocklist() {
        val filesDirectory = createFilesDirectory()
        writeSharedFixture(RuntimeDomainPolicy.activeBlocklistFile(filesDirectory))
        var resolverProviderCalls = 0

        val assembly = RuntimeDomainPolicy.assemble(
            filesDirectory = filesDirectory,
            registrableDomainResolverProvider = {
                resolverProviderCalls++
                RegistrableDomainResolver { domain ->
                    when {
                        domain == "github.com" || domain.endsWith(".github.com") -> "github.com"
                        else -> null
                    }
                }
            }
        )

        assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), assembly.compiledBlocklistStatus)
        assertEquals(1, resolverProviderCalls)
        assertTrue(assembly.matcher.shouldBlock("cdn.github.com"))
    }

    @Test
    fun malformedActiveFileIsRejectedWithoutDisablingBuiltInProtectionOrLoadingResolver() {
        val filesDirectory = createFilesDirectory()
        val activeFile = RuntimeDomainPolicy.activeBlocklistFile(filesDirectory)
        prepareParentDirectory(activeFile)
        activeFile.writeText("not a compiled blocklist")
        activeFile.deleteOnExit()
        var resolverProviderCalled = false

        val assembly = RuntimeDomainPolicy.assemble(
            filesDirectory = filesDirectory,
            registrableDomainResolverProvider = {
                resolverProviderCalled = true
                RegistrableDomainResolver { "example.com" }
            }
        )

        assertIs<CompiledBlocklistStatus.Rejected>(assembly.compiledBlocklistStatus)
        assertFalse(resolverProviderCalled)
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertFalse(assembly.matcher.shouldBlock("github.com"))
    }

    @Test
    fun malformedOverrideFallsBackToBundledBlocklistAndReportsTheSource() {
        val filesDirectory = createFilesDirectory()
        val activeFile = RuntimeDomainPolicy.activeBlocklistFile(filesDirectory)
        prepareParentDirectory(activeFile)
        activeFile.writeText("not a compiled blocklist")

        val assembly = RuntimeDomainPolicy.assemble(
            filesDirectory = filesDirectory,
            loadBundledBlocklist = ::loadSharedFixture,
            bundledSourceMetadata = RuleSourceMetadata(
                name = "Pinned test list",
                revision = "a".repeat(40),
                sourceDate = "2026-08-23"
            )
        )

        assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), assembly.compiledBlocklistStatus)
        assertEquals(RuleBlocklistSource.APK_BUNDLED, assembly.displayStatus.source)
        assertEquals("Pinned test list", assembly.displayStatus.sourceName)
        assertEquals("a".repeat(40), assembly.displayStatus.sourceRevision)
        assertEquals("2026-08-23", assembly.displayStatus.sourceDate)
        assertEquals(4, assembly.displayStatus.entryCount)
        assertEquals(RuleBlocklistValidation.APK_VERIFIED, assembly.displayStatus.validation)
        assertTrue(assembly.displayStatus.degradationReason.orEmpty().contains("本機覆寫檔未通過檢查"))
        assertTrue(assembly.matcher.shouldBlock("github.com"))
    }

    @Test
    fun rejectedOverrideAndBundledListLeaveOnlyBuiltinRulesActive() {
        val filesDirectory = createFilesDirectory()
        val activeFile = RuntimeDomainPolicy.activeBlocklistFile(filesDirectory)
        prepareParentDirectory(activeFile)
        activeFile.writeText("invalid override")

        val assembly = RuntimeDomainPolicy.assemble(
            filesDirectory = filesDirectory,
            loadBundledBlocklist = { error("APK asset checksum mismatch") }
        )

        assertIs<CompiledBlocklistStatus.Rejected>(assembly.compiledBlocklistStatus)
        assertEquals(RuleBlocklistSource.BUILT_IN, assembly.displayStatus.source)
        assertTrue(assembly.displayStatus.degradationReason.orEmpty().contains("Blocklist is smaller"))
        assertTrue(assembly.displayStatus.degradationReason.orEmpty().contains("APK asset checksum mismatch"))
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
        prepareParentDirectory(destination)
        destination.writeBytes(sharedFixtureBytes())
        destination.deleteOnExit()
    }

    private fun loadSharedFixture(): CompiledBlocklist =
        CompiledBlocklist.fromByteBuffer(java.nio.ByteBuffer.wrap(sharedFixtureBytes()))

    private fun sharedFixtureBytes(): ByteArray {
        val encoded = Files.readString(findRepositoryFixture(), StandardCharsets.US_ASCII)
        return Base64.getDecoder().decode(encoded.trim())
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
