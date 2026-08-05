package io.github.xiangwang2000.dnsshield.blocking

/**
 * Cache key that binds one normalized domain to the exact policy assembly used to decide it.
 *
 * Assembly identity is intentional. Two structurally equal assemblies still represent separate
 * publications, so a decision calculated by an old reader cannot be reused after policy reload.
 */
internal class DomainPolicyCacheKey(
    val domain: String,
    private val assembly: DomainPolicyAssembly
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DomainPolicyCacheKey) return false
        return domain == other.domain && assembly === other.assembly
    }

    override fun hashCode(): Int =
        31 * domain.hashCode() + System.identityHashCode(assembly)
}
