package io.github.xiangwang2000.dnsshield.blocking

/**
 * Resolves the registrable domain (effective TLD plus one) for a normalized DNS name.
 *
 * Implementations must apply both ICANN and PRIVATE Public Suffix List rules. Returning null keeps
 * matching exact-only, which is the safe fallback when the boundary is unknown.
 */
fun interface RegistrableDomainResolver {
    fun registrableDomain(domain: String): String?
}

/**
 * Extends an exact matcher to parent domains without crossing the registrable-domain boundary.
 *
 * The queried domain is checked first. When it is not an exact match, parents are checked from the
 * nearest parent through the registrable domain returned by [registrableDomainResolver]. Public
 * suffixes above that boundary are never passed to [exactMatcher].
 */
class ParentDomainMatcher(
    private val exactMatcher: DomainMatcher,
    private val registrableDomainResolver: RegistrableDomainResolver
) : DomainMatcher {
    override fun shouldBlock(domain: String): Boolean {
        val normalized = normalizeDomain(domain)
        if (!isUsableDomain(normalized)) return false
        if (exactMatcher.shouldBlock(normalized)) return true

        val registrableDomain = registrableDomainResolver
            .registrableDomain(normalized)
            ?.let(::normalizeDomain)
            ?.takeIf(::isRegistrableDomain)
            ?.takeIf { boundary -> isSameDomainOrSubdomain(normalized, boundary) }
            ?: return false

        var candidate = normalized
        while (candidate != registrableDomain) {
            val separator = candidate.indexOf('.')
            if (separator < 0 || separator == candidate.lastIndex) return false
            candidate = candidate.substring(separator + 1)
            if (exactMatcher.shouldBlock(candidate)) return true
        }
        return false
    }
}

private fun normalizeDomain(domain: String): String = domain.lowercase().trim()

private fun isUsableDomain(domain: String): Boolean =
    domain.isNotEmpty() &&
        domain != "unknown" &&
        !domain.startsWith('.') &&
        !domain.endsWith('.') &&
        ".." !in domain

private fun isRegistrableDomain(domain: String): Boolean =
    isUsableDomain(domain) && '.' in domain

private fun isSameDomainOrSubdomain(domain: String, boundary: String): Boolean =
    domain == boundary || domain.endsWith(".$boundary")
