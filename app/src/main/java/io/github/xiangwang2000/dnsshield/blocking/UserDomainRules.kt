package io.github.xiangwang2000.dnsshield.blocking

import java.net.IDN
import java.util.Locale

enum class DomainRuleAction {
    ALLOW,
    BLOCK
}

data class UserDomainRule(
    val domain: String,
    val action: DomainRuleAction,
    val includeSubdomains: Boolean
)

object DomainNameNormalizer {
    /** Returns a canonical ASCII DNS name, or null when [input] is not a valid domain name. */
    fun normalize(input: String): String? {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return null

        val ascii = try {
            IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES)
                .removeSuffix(".")
                .lowercase(Locale.ROOT)
        } catch (_: IllegalArgumentException) {
            return null
        }

        if (
            ascii.isEmpty() || ascii.length > MAX_DOMAIN_LENGTH || ascii.startsWith('.') ||
            ascii.endsWith('.') || ".." in ascii
        ) {
            return null
        }

        val labels = ascii.split('.')
        if (labels.any { label ->
                label.isEmpty() || label.length > MAX_LABEL_LENGTH ||
                    label.first() == '-' || label.last() == '-'
            }
        ) {
            return null
        }

        return ascii
    }

    private const val MAX_LABEL_LENGTH = 63
    private const val MAX_DOMAIN_LENGTH = 253
}

/** An immutable snapshot of user rules, resolved by the most-specific matching domain. */
class UserDomainRuleMatcher(rules: Iterable<UserDomainRule>) {
    private val rulesByDomain: Map<String, RulesAtDomain>

    init {
        val mutableRules = LinkedHashMap<String, MutableRulesAtDomain>()
        for (rule in rules) {
            val domain = DomainNameNormalizer.normalize(rule.domain) ?: continue
            val atDomain = mutableRules.getOrPut(domain, ::MutableRulesAtDomain)
            if (rule.includeSubdomains) {
                atDomain.includeSubdomains = rule.action
            } else {
                atDomain.exact = rule.action
            }
        }
        rulesByDomain = mutableRules.mapValues { (_, rulesAtDomain) ->
            RulesAtDomain(
                exact = rulesAtDomain.exact,
                includeSubdomains = rulesAtDomain.includeSubdomains
            )
        }
    }

    fun decisionFor(domain: String): DomainRuleAction? {
        val normalized = DomainNameNormalizer.normalize(domain) ?: return null

        val atQuery = rulesByDomain[normalized]
        // When both scopes exist on the queried apex, the exact rule is more specific.
        atQuery?.exact?.let { return it }
        atQuery?.includeSubdomains?.let { return it }

        var separator = normalized.indexOf('.')
        while (separator >= 0) {
            val parent = normalized.substring(separator + 1)
            rulesByDomain[parent]?.includeSubdomains?.let { return it }
            separator = normalized.indexOf('.', separator + 1)
        }

        return null
    }

    private data class RulesAtDomain(
        val exact: DomainRuleAction?,
        val includeSubdomains: DomainRuleAction?
    )

    private class MutableRulesAtDomain(
        var exact: DomainRuleAction? = null,
        var includeSubdomains: DomainRuleAction? = null
    )
}
