package io.github.xiangwang2000.dnsshield.blocking

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DomainPolicyTest {
    @Test
    fun allowlistTakesPrecedenceOverEveryBlocker() {
        var blockerCalls = 0
        val alwaysBlocks = DomainMatcher {
            blockerCalls++
            true
        }
        val matcher = CompositeDomainMatcher(
            allowlist = ExactDomainAllowlist(listOf("safe.example")),
            blockers = listOf(alwaysBlocks, alwaysBlocks)
        )

        assertFalse(matcher.shouldBlock(" SAFE.EXAMPLE "))
        assertEquals(0, blockerCalls)
    }

    @Test
    fun exactAllowlistDoesNotPermitSubdomainsOrLookalikes() {
        val matcher = CompositeDomainMatcher(
            allowlist = ExactDomainAllowlist(listOf("example.com")),
            blockers = listOf(DomainMatcher { true })
        )

        assertFalse(matcher.shouldBlock("example.com"))
        assertTrue(matcher.shouldBlock("sub.example.com"))
        assertTrue(matcher.shouldBlock("lookalike-example.com"))
    }

    @Test
    fun blockersRunInOrderAndShortCircuitOnFirstBlock() {
        val calls = mutableListOf<String>()
        val matcher = CompositeDomainMatcher(
            blockers = listOf(
                DomainMatcher {
                    calls += "first"
                    false
                },
                DomainMatcher {
                    calls += "second"
                    true
                },
                DomainMatcher {
                    calls += "third"
                    true
                }
            )
        )

        assertTrue(matcher.shouldBlock("ads.example"))
        assertEquals(listOf("first", "second"), calls)
    }

    @Test
    fun returnsAllowedWhenNoBlockerMatches() {
        val matcher = CompositeDomainMatcher(
            blockers = listOf(DomainMatcher { false }, DomainMatcher { false })
        )

        assertFalse(matcher.shouldBlock("example.com"))
    }

    @Test
    fun ignoresBlankAndUnknownWithoutCallingPolicies() {
        var policyCalls = 0
        val matcher = CompositeDomainMatcher(
            allowlist = DomainAllowlist {
                policyCalls++
                false
            },
            blockers = listOf(DomainMatcher {
                policyCalls++
                true
            })
        )

        assertFalse(matcher.shouldBlock(""))
        assertFalse(matcher.shouldBlock(" Unknown "))
        assertEquals(0, policyCalls)
    }

    @Test
    fun snapshotsMutableInputsAtConstruction() {
        val allowlistEntries = mutableListOf("safe.example")
        val blockers = mutableListOf<DomainMatcher>(DomainMatcher { false })
        val matcher = CompositeDomainMatcher(
            allowlist = ExactDomainAllowlist(allowlistEntries),
            blockers = blockers
        )

        allowlistEntries += "later.example"
        blockers += DomainMatcher { true }

        assertFalse(matcher.shouldBlock("safe.example"))
        assertFalse(matcher.shouldBlock("later.example"))
    }

    @Test
    fun emptyAllowlistEntriesAreIgnored() {
        val allowlist = ExactDomainAllowlist(listOf("", "  ", "unknown", " UNKNOWN "))

        assertFalse(allowlist.isAllowed(""))
        assertFalse(allowlist.isAllowed("unknown"))
        assertFalse(allowlist.isAllowed("example.com"))
    }
}
