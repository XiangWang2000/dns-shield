package io.github.xiangwang2000.dnsshield.blocking

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class UserDomainRuleValidatorTest {
    private val resolver = RegistrableDomainResolver { domain ->
        when {
            domain == "co.uk" || domain == "github.io" -> null
            domain.endsWith(".co.uk") -> domain.split('.').takeLast(3).joinToString(".")
            domain.endsWith(".github.io") -> domain.split('.').takeLast(3).joinToString(".")
            else -> domain.split('.').takeLast(2).joinToString(".")
        }
    }

    @Test
    fun normalizesDomainBeforePublicSuffixValidation() {
        val result = UserDomainRuleValidator.validate(
            domain = "  SHOP.BÜCHER.example. ",
            action = DomainRuleAction.ALLOW,
            includeSubdomains = true,
            resolver = resolver
        )

        val valid = assertIs<UserDomainRuleValidation.Valid>(result)
        assertEquals("shop.xn--bcher-kva.example", valid.rule.domain)
    }

    @Test
    fun rejectsPublicSuffixScopeButAllowsExactPublicSuffixEntry() {
        val broad = UserDomainRuleValidator.validate(
            domain = "co.uk",
            action = DomainRuleAction.ALLOW,
            includeSubdomains = true,
            resolver = resolver
        )
        val exact = UserDomainRuleValidator.validate(
            domain = "co.uk",
            action = DomainRuleAction.BLOCK,
            includeSubdomains = false
        )

        assertEquals(
            UserDomainRuleValidation.Reason.PUBLIC_SUFFIX_DOMAIN,
            assertIs<UserDomainRuleValidation.Invalid>(broad).reason
        )
        assertIs<UserDomainRuleValidation.Valid>(exact)
    }

    @Test
    fun acceptsARegistrableSubdomainScope() {
        val result = UserDomainRuleValidator.validate(
            domain = "api.tenant.github.io",
            action = DomainRuleAction.BLOCK,
            includeSubdomains = true,
            resolver = resolver
        )

        assertIs<UserDomainRuleValidation.Valid>(result)
    }

    @Test
    fun failsClosedWhenPublicSuffixDataIsUnavailable() {
        val result = UserDomainRuleValidator.validate(
            domain = "example.com",
            action = DomainRuleAction.ALLOW,
            includeSubdomains = true
        )

        assertEquals(
            UserDomainRuleValidation.Reason.PUBLIC_SUFFIX_RESOLVER_UNAVAILABLE,
            assertIs<UserDomainRuleValidation.Invalid>(result).reason
        )
    }
}
