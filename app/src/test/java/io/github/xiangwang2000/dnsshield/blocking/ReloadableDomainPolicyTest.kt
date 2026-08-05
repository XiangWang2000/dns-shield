package io.github.xiangwang2000.dnsshield.blocking

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ReloadableDomainPolicyTest {
    @Test
    fun startsWithProvidedAssembly() {
        val initial = assembly(
            blockedDomain = "initial.example",
            status = CompiledBlocklistStatus.Loaded(entryCount = 1)
        )
        val policy = ReloadableDomainPolicy(initial)

        assertSame(initial, policy.snapshot())
        assertTrue(policy.shouldBlock("initial.example"))
        assertFalse(policy.shouldBlock("replacement.example"))
    }

    @Test
    fun runsInvalidationBeforePublishingReplacement() {
        val initial = assembly(
            blockedDomain = "initial.example",
            status = CompiledBlocklistStatus.NotConfigured
        )
        val replacement = assembly(
            blockedDomain = "replacement.example",
            status = CompiledBlocklistStatus.Loaded(entryCount = 4)
        )
        val policy = ReloadableDomainPolicy(initial)
        var invalidationRan = false

        val installedStatus = policy.install(replacement) {
            invalidationRan = true
            assertSame(initial, policy.snapshot())
            assertTrue(policy.shouldBlock("initial.example"))
            assertFalse(policy.shouldBlock("replacement.example"))
        }

        assertTrue(invalidationRan)
        assertEquals(CompiledBlocklistStatus.Loaded(entryCount = 4), installedStatus)
        assertSame(replacement, policy.snapshot())
        assertFalse(policy.shouldBlock("initial.example"))
        assertTrue(policy.shouldBlock("replacement.example"))
    }

    @Test
    fun failedInvalidationPreservesExistingPolicy() {
        val initial = assembly(
            blockedDomain = "initial.example",
            status = CompiledBlocklistStatus.NotConfigured
        )
        val replacement = assembly(
            blockedDomain = "replacement.example",
            status = CompiledBlocklistStatus.Rejected("synthetic rejection")
        )
        val policy = ReloadableDomainPolicy(initial)

        val failure = assertFailsWith<IllegalStateException> {
            policy.install(replacement) {
                throw IllegalStateException("cache invalidation failed")
            }
        }

        assertEquals("cache invalidation failed", failure.message)
        assertSame(initial, policy.snapshot())
        assertTrue(policy.shouldBlock("initial.example"))
        assertFalse(policy.shouldBlock("replacement.example"))
    }

    @Test
    fun defaultInstallationPublishesMatcherAndStatusTogether() {
        val policy = ReloadableDomainPolicy(
            assembly(
                blockedDomain = "initial.example",
                status = CompiledBlocklistStatus.NotConfigured
            )
        )
        val replacement = assembly(
            blockedDomain = "replacement.example",
            status = CompiledBlocklistStatus.Rejected("invalid artifact")
        )

        val installedStatus = policy.install(replacement)
        val snapshot = policy.snapshot()

        assertEquals(CompiledBlocklistStatus.Rejected("invalid artifact"), installedStatus)
        assertSame(replacement, snapshot)
        assertEquals(installedStatus, snapshot.compiledBlocklistStatus)
        assertTrue(snapshot.matcher.shouldBlock("replacement.example"))
        assertFalse(snapshot.matcher.shouldBlock("initial.example"))
    }

    private fun assembly(
        blockedDomain: String,
        status: CompiledBlocklistStatus
    ): DomainPolicyAssembly = DomainPolicyAssembly(
        matcher = DomainMatcher { domain -> domain == blockedDomain },
        compiledBlocklistStatus = status
    )
}
