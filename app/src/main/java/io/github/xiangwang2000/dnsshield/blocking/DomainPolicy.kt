package io.github.xiangwang2000.dnsshield.blocking

/** Decides whether a normalized DNS domain must bypass all blocking matchers. */
fun interface DomainAllowlist {
    fun isAllowed(domain: String): Boolean

    companion object {
        val NONE: DomainAllowlist = DomainAllowlist { false }
    }
}

/**
 * Immutable exact-domain allowlist.
 *
 * Entries are normalized with the same lowercase-and-trim contract as the current matchers.
 * Exact matching is intentional: allowing example.com does not automatically allow
 * sub.example.com or lookalike-example.com. Parent-domain policy remains a separate decision.
 */
class ExactDomainAllowlist(domains: Iterable<String>) : DomainAllowlist {
    private val allowedDomains = domains
        .asSequence()
        .map(::normalizeDomain)
        .filter(::isUsableDomain)
        .toSet()

    override fun isAllowed(domain: String): Boolean {
        val normalized = normalizeDomain(domain)
        return isUsableDomain(normalized) && normalized in allowedDomains
    }
}

/**
 * Applies user-domain rules and the exact legacy allowlist before blocking matchers.
 *
 * The matcher list is snapshotted at construction time. Blocking short-circuits on the first
 * positive result. A matching user rule overrides the protection lists; within the user rules, the
 * most-specific matching domain wins and an exact rule wins over a same-domain subdomain rule at
 * the apex.
 */
class CompositeDomainMatcher(
    private val allowlist: DomainAllowlist = DomainAllowlist.NONE,
    blockers: Iterable<DomainMatcher>,
    private val userRules: UserDomainRuleMatcher = UserDomainRuleMatcher(emptyList())
) : DomainMatcher {
    private val blockers = blockers.toList()

    override fun shouldBlock(domain: String): Boolean {
        val normalized = normalizeDomain(domain)
        if (!isUsableDomain(normalized)) return false
        when (userRules.decisionFor(normalized)) {
            DomainRuleAction.ALLOW -> return false
            DomainRuleAction.BLOCK -> return true
            null -> Unit
        }
        if (allowlist.isAllowed(normalized)) return false
        return blockers.any { it.shouldBlock(normalized) }
    }
}

private fun normalizeDomain(domain: String): String = domain.lowercase().trim()

private fun isUsableDomain(domain: String): Boolean =
    domain.isNotEmpty() && domain != "unknown"
