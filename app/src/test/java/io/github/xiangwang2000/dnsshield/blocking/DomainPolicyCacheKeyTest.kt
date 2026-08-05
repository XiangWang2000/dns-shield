package io.github.xiangwang2000.dnsshield.blocking

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class DomainPolicyCacheKeyTest {
    @Test
    fun sameDomainAndAssemblyShareOneKey() {
        val assembly = assembly()

        val first = DomainPolicyCacheKey("example.com", assembly)
        val second = DomainPolicyCacheKey("example.com", assembly)

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
    }

    @Test
    fun separatePolicyPublicationsDoNotShareCachedDecisions() {
        val matcher = DomainMatcher { false }
        val firstAssembly = DomainPolicyAssembly(
            matcher = matcher,
            compiledBlocklistStatus = CompiledBlocklistStatus.NotConfigured
        )
        val secondAssembly = DomainPolicyAssembly(
            matcher = matcher,
            compiledBlocklistStatus = CompiledBlocklistStatus.NotConfigured
        )

        assertNotEquals(
            DomainPolicyCacheKey("example.com", firstAssembly),
            DomainPolicyCacheKey("example.com", secondAssembly)
        )
    }

    @Test
    fun differentDomainsDoNotShareOneKey() {
        val assembly = assembly()

        assertNotEquals(
            DomainPolicyCacheKey("example.com", assembly),
            DomainPolicyCacheKey("sub.example.com", assembly)
        )
    }

    private fun assembly() = DomainPolicyAssembly(
        matcher = DomainMatcher { false },
        compiledBlocklistStatus = CompiledBlocklistStatus.NotConfigured
    )
}
