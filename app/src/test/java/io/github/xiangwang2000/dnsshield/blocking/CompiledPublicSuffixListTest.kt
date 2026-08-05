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
import kotlin.test.assertNull

class CompiledPublicSuffixListTest {
    @Test
    fun readsSharedCompilerFixtureAndPinnedSourceHash() {
        val resolver = readSharedFixture()

        assertEquals(9, resolver.exactRuleCount)
        assertEquals(2, resolver.wildcardRuleCount)
        assertEquals(2, resolver.exceptionRuleCount)
        assertEquals(
            "73eccadbfd06a1e7e5ca4cbb001fcdb39d65f04766588281e2fa4c677cf5a72b",
            resolver.sourceSha256Hex
        )
    }

    @Test
    fun resolvesIcannMultiLabelAndPrivateSuffixBoundaries() {
        val resolver = readSharedFixture()

        assertEquals("example.com", resolver.registrableDomain(" ADS.EXAMPLE.COM "))
        assertEquals("example.co.uk", resolver.registrableDomain("a.b.example.co.uk"))
        assertEquals("tenant.github.io", resolver.registrableDomain("ads.tenant.github.io"))
        assertEquals("site.blogspot.com", resolver.registrableDomain("cdn.site.blogspot.com"))
        assertNull(resolver.registrableDomain("github.io"))
        assertNull(resolver.registrableDomain("co.uk"))
    }

    @Test
    fun appliesWildcardRulesWithoutCrossingTheirMatchedSuffix() {
        val resolver = readSharedFixture()

        assertEquals("a.b.ck", resolver.registrableDomain("a.b.ck"))
        assertNull(resolver.registrableDomain("b.ck"))
        assertNull(resolver.registrableDomain("foo.kawasaki.jp"))
        assertEquals(
            "a.foo.kawasaki.jp",
            resolver.registrableDomain("a.foo.kawasaki.jp")
        )
    }

    @Test
    fun exceptionRulesOverrideMatchingWildcards() {
        val resolver = readSharedFixture()

        assertEquals("www.ck", resolver.registrableDomain("www.ck"))
        assertEquals("www.ck", resolver.registrableDomain("a.www.ck"))
        assertEquals(
            "city.kawasaki.jp",
            resolver.registrableDomain("city.kawasaki.jp")
        )
        assertEquals(
            "city.kawasaki.jp",
            resolver.registrableDomain("a.city.kawasaki.jp")
        )
    }

    @Test
    fun unknownSuffixUsesThePublicSuffixDefaultRule() {
        val resolver = readSharedFixture()

        assertEquals("example.unknown", resolver.registrableDomain("a.example.unknown"))
        assertNull(resolver.registrableDomain("unknown"))
    }

    @Test
    fun rejectsUnusableDomainInputs() {
        val resolver = readSharedFixture()

        assertNull(resolver.registrableDomain(""))
        assertNull(resolver.registrableDomain(" unknown "))
        assertNull(resolver.registrableDomain(".example.com"))
        assertNull(resolver.registrableDomain("example.com."))
        assertNull(resolver.registrableDomain("a..example.com"))
        assertNull(resolver.registrableDomain("-bad.example.com"))
        assertNull(resolver.registrableDomain("bad-.example.com"))
        assertNull(resolver.registrableDomain("bad domain.example"))
    }

    @Test
    fun requiresPrivateRulesAndRejectsUnsupportedFlags() {
        val artifact = decodeSharedFixture()

        val withoutPrivate = artifact.clone().apply {
            ByteBuffer.wrap(this).order(ByteOrder.LITTLE_ENDIAN).putInt(12, 0)
        }
        assertFailsWith<IllegalArgumentException> {
            CompiledPublicSuffixList.fromByteBuffer(ByteBuffer.wrap(withoutPrivate))
        }

        val unsupportedFlags = artifact.clone().apply {
            ByteBuffer.wrap(this).order(ByteOrder.LITTLE_ENDIAN).putInt(12, 3)
        }
        assertFailsWith<IllegalArgumentException> {
            CompiledPublicSuffixList.fromByteBuffer(ByteBuffer.wrap(unsupportedFlags))
        }
    }

    @Test
    fun rejectsTruncatedAndTrailingArtifacts() {
        val artifact = decodeSharedFixture()

        assertFailsWith<IllegalArgumentException> {
            CompiledPublicSuffixList.fromByteBuffer(
                ByteBuffer.wrap(artifact.copyOf(artifact.size - 1))
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CompiledPublicSuffixList.fromByteBuffer(
                ByteBuffer.wrap(artifact + byteArrayOf(0))
            )
        }
    }

    @Test
    fun rejectsRuleMarkersInsideEncodedRules() {
        val sourceHash = ByteArray(32)
        val malformedRule = "bad.*.rule".toByteArray(StandardCharsets.UTF_8)
        val artifact = ByteBuffer.allocate(60 + 2 + malformedRule.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put("DNSHPS01".toByteArray(StandardCharsets.US_ASCII))
            .putInt(1)
            .putInt(1)
            .putInt(1)
            .putInt(0)
            .putInt(0)
            .put(sourceHash)
            .putShort(malformedRule.size.toShort())
            .put(malformedRule)
            .array()

        assertFailsWith<IllegalArgumentException> {
            CompiledPublicSuffixList.fromByteBuffer(ByteBuffer.wrap(artifact))
        }
    }

    @Test
    fun rejectsUnsortedRuleTables() {
        val sourceHash = ByteArray(32)
        val artifact = ByteBuffer.allocate(60 + 2 + 3 + 2 + 2)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put("DNSHPS01".toByteArray(StandardCharsets.US_ASCII))
            .putInt(1)
            .putInt(1)
            .putInt(2)
            .putInt(0)
            .putInt(0)
            .put(sourceHash)
            .putShort(3.toShort())
            .put("com".toByteArray(StandardCharsets.UTF_8))
            .putShort(2.toShort())
            .put("ck".toByteArray(StandardCharsets.UTF_8))
            .array()

        assertFailsWith<IllegalArgumentException> {
            CompiledPublicSuffixList.fromByteBuffer(ByteBuffer.wrap(artifact))
        }
    }

    private fun readSharedFixture(): CompiledPublicSuffixList =
        CompiledPublicSuffixList.fromByteBuffer(ByteBuffer.wrap(decodeSharedFixture()))

    private fun decodeSharedFixture(): ByteArray {
        val encoded = Files.readString(findRepositoryFixture(), StandardCharsets.US_ASCII)
        return Base64.getDecoder().decode(encoded.trim())
    }

    private fun findRepositoryFixture(): Path {
        val relative = Paths.get(
            "tools",
            "tests",
            "fixtures",
            "public_suffix.bin.base64"
        )
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
