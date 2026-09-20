package io.github.xiangwang2000.dnsshield.blocking

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class UserDomainRulePolicyTest {
    @Test
    fun userAllowRuleOverridesBuiltInBlockAtItsConfiguredScope() {
        val assembly = DomainPolicyAssembler.assemble(
            userRules = listOf(
                UserDomainRule("doubleclick.net", DomainRuleAction.ALLOW, includeSubdomains = false)
            )
        )

        assertFalse(assembly.matcher.shouldBlock("doubleclick.net"))
        assertTrue(assembly.matcher.shouldBlock("ads.doubleclick.net"))
    }

    @Test
    fun moreSpecificUserRuleOverridesBroaderRuleAndProtectionLists() {
        val assembly = DomainPolicyAssembler.assemble(
            userRules = listOf(
                UserDomainRule("example.com", DomainRuleAction.ALLOW, includeSubdomains = true),
                UserDomainRule("tracker.example.com", DomainRuleAction.BLOCK, includeSubdomains = false)
            )
        )

        assertFalse(assembly.matcher.shouldBlock("ads.example.com"))
        assertTrue(assembly.matcher.shouldBlock("tracker.example.com"))
        assertFalse(assembly.matcher.shouldBlock("lookalike-example.com"))
    }

    @Test
    fun userBlockRuleOverridesDefaultPolicyAndAppliesOnlyWithinItsScope() {
        val assembly = DomainPolicyAssembler.assemble(
            userRules = listOf(
                UserDomainRule("custom.example", DomainRuleAction.BLOCK, includeSubdomains = true)
            )
        )

        assertTrue(assembly.matcher.shouldBlock("custom.example"))
        assertTrue(assembly.matcher.shouldBlock("api.custom.example"))
        assertFalse(assembly.matcher.shouldBlock("custom-example"))
    }

    @Test
    fun replacementSnapshotPublishesAfterTheInvalidationCallback() {
        val initial = DomainPolicyAssembler.assemble(
            userRules = listOf(
                UserDomainRule("ads.doubleclick.net", DomainRuleAction.ALLOW, includeSubdomains = false)
            )
        )
        val replacement = DomainPolicyAssembler.assemble(
            userRules = listOf(
                UserDomainRule("ads.doubleclick.net", DomainRuleAction.BLOCK, includeSubdomains = false)
            )
        )
        val policy = ReloadableDomainPolicy(initial)
        var invalidationRan = false

        policy.install(replacement) {
            invalidationRan = true
            assertSame(initial, policy.snapshot())
            assertFalse(policy.shouldBlock("ads.doubleclick.net"))
        }

        assertTrue(invalidationRan)
        assertSame(replacement, policy.snapshot())
        assertTrue(policy.shouldBlock("ads.doubleclick.net"))
    }
}
