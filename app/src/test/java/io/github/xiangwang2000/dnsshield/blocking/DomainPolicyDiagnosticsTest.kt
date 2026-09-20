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

class DomainPolicyDiagnosticsTest {
    @Test
    fun logsNotConfiguredAndKeepsBuiltInBlockingWhenActiveFileIsMissing() {
        val filesDirectory = Files.createTempDirectory("dns-shield-diagnostics-missing-").toFile()

        val assembly = RuntimeDomainPolicy.assemble(filesDirectory)

        assertEquals(CompiledBlocklistStatus.NotConfigured, assembly.compiledBlocklistStatus)
        assertEquals(
            "[攔截規則] 未設定 compiled blocklist，使用內建規則",
            DomainPolicyDiagnostics.message(assembly.compiledBlocklistStatus)
        )
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertFalse(assembly.matcher.shouldBlock("github.com"))
    }

    @Test
    fun logsLoadedCountAndKeepsBuiltInBlockingForFourEntryArtifact() {
        val filesDirectory = Files.createTempDirectory("dns-shield-diagnostics-loaded-").toFile()
        val activeFile = RuntimeDomainPolicy.activeBlocklistFile(filesDirectory)
        prepareParentDirectory(activeFile)
        activeFile.writeBytes(Base64.getDecoder().decode(
            Files.readString(findRepositoryFixture(), StandardCharsets.US_ASCII).trim()
        ))

        val assembly = RuntimeDomainPolicy.assemble(filesDirectory)

        assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), assembly.compiledBlocklistStatus)
        assertEquals(
            "[攔截規則] 已載入 compiled blocklist：4 筆",
            DomainPolicyDiagnostics.message(assembly.compiledBlocklistStatus)
        )
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertTrue(assembly.matcher.shouldBlock("github.com"))
        assertFalse(assembly.matcher.shouldBlock("example.com"))
    }

    @Test
    fun logsRejectedReasonAndKeepsBuiltInBlockingForMalformedArtifact() {
        val filesDirectory = Files.createTempDirectory("dns-shield-diagnostics-rejected-").toFile()
        val activeFile = RuntimeDomainPolicy.activeBlocklistFile(filesDirectory)
        prepareParentDirectory(activeFile)
        activeFile.writeText("not a compiled blocklist")

        val assembly = RuntimeDomainPolicy.assemble(filesDirectory)

        val rejected = assertIs<CompiledBlocklistStatus.Rejected>(assembly.compiledBlocklistStatus)
        val log = DomainPolicyDiagnostics.message(rejected)
        assertTrue(log.startsWith("[攔截規則] compiled blocklist 無法載入，已回退內建規則："))
        assertTrue(log.endsWith(rejected.reason))
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
        assertFalse(assembly.matcher.shouldBlock("github.com"))
    }

    @Test
    fun displaysSourceValidationAndPublicSuffixDegradationSeparately() {
        val lines = DomainPolicyDiagnostics.details(
            RulePolicyStatus(
                source = RuleBlocklistSource.APK_BUNDLED,
                sourceName = "Pinned list",
                sourceRevision = "revision-123",
                sourceDate = "2026-08-23",
                entryCount = 102_972,
                validation = RuleBlocklistValidation.APK_VERIFIED,
                degradationReason = "本機 override 無效，已改用 APK 清單",
                publicSuffixStatus = PublicSuffixResolverStatus.Rejected("bad PSL asset")
            )
        )

        assertTrue(lines.contains("規則來源：APK 內建清單（Pinned list）"))
        assertTrue(lines.contains("來源 revision：revision-123"))
        assertTrue(lines.contains("來源日期：2026-08-23"))
        assertTrue(lines.contains("規則數：102972 筆"))
        assertTrue(lines.contains("驗證狀態：APK 清單完整性驗證通過"))
        assertTrue(lines.any { it.contains("降級原因：") && it.contains("改用 APK 清單") })
        assertTrue(lines.any { it.contains("Public Suffix List 載入失敗") && it.contains("精確網域比對") })
        assertTrue(lines.any { it.contains("bad PSL asset") })
    }

    private fun prepareParentDirectory(file: File) {
        val parent = requireNotNull(file.parentFile)
        check(parent.mkdirs() || parent.isDirectory)
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
