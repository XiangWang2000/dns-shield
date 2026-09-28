package io.github.xiangwang2000.dnsshield.blocking

sealed interface UserDomainRuleValidation {
    data class Valid(val rule: UserDomainRule) : UserDomainRuleValidation

    data class Invalid(val reason: Reason) : UserDomainRuleValidation

    enum class Reason {
        INVALID_DOMAIN,
        PUBLIC_SUFFIX_RESOLVER_UNAVAILABLE,
        PUBLIC_SUFFIX_DOMAIN
    }
}

/** Normalizes user input and prevents a subdomain rule from crossing a Public Suffix boundary. */
object UserDomainRuleValidator {
    fun validate(
        domain: String,
        action: DomainRuleAction,
        includeSubdomains: Boolean,
        resolver: RegistrableDomainResolver? = null
    ): UserDomainRuleValidation {
        val normalized = DomainNameNormalizer.normalize(domain)
            ?: return UserDomainRuleValidation.Invalid(
                UserDomainRuleValidation.Reason.INVALID_DOMAIN
            )

        if (includeSubdomains) {
            val registrableDomain = try {
                resolver?.registrableDomain(normalized)
                    ?: return UserDomainRuleValidation.Invalid(
                        if (resolver == null) {
                            UserDomainRuleValidation.Reason.PUBLIC_SUFFIX_RESOLVER_UNAVAILABLE
                        } else {
                            UserDomainRuleValidation.Reason.PUBLIC_SUFFIX_DOMAIN
                        }
                    )
            } catch (_: Exception) {
                return UserDomainRuleValidation.Invalid(
                    UserDomainRuleValidation.Reason.PUBLIC_SUFFIX_RESOLVER_UNAVAILABLE
                )
            }
            if (DomainNameNormalizer.normalize(registrableDomain) == null) {
                return UserDomainRuleValidation.Invalid(
                    UserDomainRuleValidation.Reason.PUBLIC_SUFFIX_RESOLVER_UNAVAILABLE
                )
            }
        }

        return UserDomainRuleValidation.Valid(
            UserDomainRule(
                domain = normalized,
                action = action,
                includeSubdomains = includeSubdomains
            )
        )
    }
}
