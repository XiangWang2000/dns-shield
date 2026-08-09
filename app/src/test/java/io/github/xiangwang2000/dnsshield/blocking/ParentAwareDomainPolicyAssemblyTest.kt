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
import kotlin.test.assertTrue

class ParentAwareDomainPolicyAssemblyTest {
    @Test
    fun doesNotResolvePublicSuffixWhenCompiledBlocklistIsMissing() {
        var resolverProviderCalls = 0

        val assembly = DomainPolicyAssembler.assemble(
            registrableDomainResolverProvider = {
                resolverProviderCalls++
                RegistrableDomainResolver { "example.com" }
            }
        )

        assertEquals(CompiledBlocklistStatus.NotConfigured, assembly.compiledBlocklistStatus)
        assertEquals(0, resolverProviderCalls)
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
    }

    @Test
    fun extendsValidatedCompiledBlocklistThroughRegistrableBoundary() {
        var resolverProviderCalls = 0
        val assembly = DomainPolicyAssembler.assemble(
            compiledBlocklistFile = writeSharedFixtureToTemporaryFile(),
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
        assertTrue(assembly.matcher.shouldBlock("github.com"))
        assertTrue(assembly.matcher.shouldBlock("cdn.github.com"))
        assertFalse(assembly.matcher.shouldBlock("example.com"))
    }

    @Test
    fun unavailableResolverKeepsValidatedCompiledMatcherExactOnly() {
        val assembly = DomainPolicyAssembler.assemble(
            compiledBlocklistFile = writeSharedFixtureToTemporaryFile(),
            registrableDomainResolverProvider = { null }
        )

        assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), assembly.compiledBlocklistStatus)
        assertTrue(assembly.matcher.shouldBlock("github.com"))
        assertFalse(assembly.matcher.shouldBlock("cdn.github.com"))
    }

    @Test
    fun resolverProviderFailureKeepsValidatedCompiledMatcherExactOnly() {
        val assembly = DomainPolicyAssembler.assemble(
            compiledBlocklistFile = writeSharedFixtureToTemporaryFile(),
            registrableDomainResolverProvider = {
                throw IllegalStateException("synthetic Public Suffix failure")
            }
        )

        assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), assembly.compiledBlocklistStatus)
        assertTrue(assembly.matcher.shouldBlock("github.com"))
        assertFalse(assembly.matcher.shouldBlock("cdn.github.com"))
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
    }

    @Test
    fun exactAllowlistDoesNotBecomeParentAware() {
        val assembly = DomainPolicyAssembler.assemble(
            compiledBlocklistFile = writeSharedFixtureToTemporaryFile(),
            allowlist = ExactDomainAllowlist(listOf("github.com")),
            registrableDomainResolverProvider = {
                RegistrableDomainResolver { domain ->
                    when {
                        domain == "github.com" || domain.endsWith(".github.com") -> "github.com"
                        else -> null
                    }
                }
            }
        )

        assertFalse(assembly.matcher.shouldBlock("github.com"))
        assertTrue(assembly.matcher.shouldBlock("cdn.github.com"))
    }

    @Test
    fun malformedCompiledBlocklistDoesNotResolvePublicSuffix() {
        val malformedFile = File.createTempFile("dns-shield-malformed-parent-", ".bin").apply {
            writeText("not a compiled blocklist")
            deleteOnExit()
        }
        var resolverProviderCalls = 0

        val assembly = DomainPolicyAssembler.assemble(
            compiledBlocklistFile = malformedFile,
            registrableDomainResolverProvider = {
                resolverProviderCalls++
                RegistrableDomainResolver { "example.com" }
            }
        )

        assertTrue(assembly.compiledBlocklistStatus is CompiledBlocklistStatus.Rejected)
        assertEquals(0, resolverProviderCalls)
        assertTrue(assembly.matcher.shouldBlock("admob.com"))
    }

    private fun writeSharedFixtureToTemporaryFile(): File {
        val encoded = Files.readString(findRepositoryFixture(), StandardCharsets.US_ASCII)
        return File.createTempFile("dns-shield-parent-aware-", ".bin").apply {
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
