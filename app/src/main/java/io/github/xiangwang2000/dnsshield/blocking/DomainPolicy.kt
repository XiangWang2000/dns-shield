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
 * Applies allowlist precedence before asking blocking matchers in order.
 *
 * The matcher list is snapshotted at construction time. Blocking short-circuits on the first
 * positive result, while an allowlist hit bypasses every blocker.
 */
class CompositeDomainMatcher(
    private val allowlist: DomainAllowlist = DomainAllowlist.NONE,
    blockers: Iterable<DomainMatcher>
) : DomainMatcher {
    private val blockers = blockers.toList()

    override fun shouldBlock(domain: String): Boolean {
        val normalized = normalizeDomain(domain)
        if (!isUsableDomain(normalized)) return false
        if (allowlist.isAllowed(normalized)) return false
        return blockers.any { it.shouldBlock(normalized) }
    }
}

private fun normalizeDomain(domain: String): String = domain.lowercase().trim()

private fun isUsableDomain(domain: String): Boolean =
    domain.isNotEmpty() && domain != "unknown"
