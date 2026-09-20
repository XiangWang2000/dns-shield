package io.github.xiangwang2000.dnsshield.blocking

import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UserDomainRulesTest {
    @Test
    fun normalizesIdnCaseAndOneTrailingDot() {
        assertEquals(
            "xn--bcher-kva.example",
            DomainNameNormalizer.normalize("  BÜCHER.Example.  ")
        )
    }

    @Test
    fun lowercasesWithRootLocale() {
        val previousLocale = Locale.getDefault()
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"))

            assertEquals("i.example", DomainNameNormalizer.normalize("I.EXAMPLE"))
        } finally {
            Locale.setDefault(previousLocale)
        }
    }

    @Test
    fun rejectsMalformedAndOverlongNames() {
        val invalidNames = listOf(
            "",
            "   ",
            ".example.com",
            "example.com..",
            "a..example.com",
            "_service.example.com",
            "-bad.example.com",
            "bad-.example.com",
            "example.com:443",
            "a".repeat(64) + ".example",
            listOf("a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(62))
                .joinToString(".")
        )

        invalidNames.forEach { name ->
            assertNull(DomainNameNormalizer.normalize(name), "Expected invalid domain: $name")
        }
    }

    @Test
    fun exactRuleMatchesOnlyApex() {
        val matcher = matcher(
            UserDomainRule("example.com", DomainRuleAction.BLOCK, includeSubdomains = false)
        )

        assertEquals(DomainRuleAction.BLOCK, matcher.decisionFor("example.com"))
        assertNull(matcher.decisionFor("www.example.com"))
    }

    @Test
    fun includeSubdomainsRuleMatchesApexAndDescendants() {
        val matcher = matcher(
            UserDomainRule("example.com", DomainRuleAction.ALLOW, includeSubdomains = true)
        )

        assertEquals(DomainRuleAction.ALLOW, matcher.decisionFor("example.com"))
        assertEquals(DomainRuleAction.ALLOW, matcher.decisionFor("a.b.example.com"))
    }

    @Test
    fun suffixLookalikesDoNotMatch() {
        val matcher = matcher(
            UserDomainRule("example.com", DomainRuleAction.BLOCK, includeSubdomains = true)
        )

        assertNull(matcher.decisionFor("lookalike-example.com"))
        assertNull(matcher.decisionFor("example.com.attacker.test"))
    }

    @Test
    fun mostSpecificMatchingDomainWins() {
        val matcher = matcher(
            UserDomainRule("example.com", DomainRuleAction.BLOCK, includeSubdomains = true),
            UserDomainRule("allowed.example.com", DomainRuleAction.ALLOW, includeSubdomains = true)
        )

        assertEquals(DomainRuleAction.BLOCK, matcher.decisionFor("other.example.com"))
        assertEquals(DomainRuleAction.ALLOW, matcher.decisionFor("allowed.example.com"))
        assertEquals(DomainRuleAction.ALLOW, matcher.decisionFor("child.allowed.example.com"))
    }

    @Test
    fun exactRuleWinsOverIncludeRuleOnSameApex() {
        val matcher = matcher(
            UserDomainRule("example.com", DomainRuleAction.ALLOW, includeSubdomains = true),
            UserDomainRule("EXAMPLE.COM.", DomainRuleAction.BLOCK, includeSubdomains = false)
        )

        assertEquals(DomainRuleAction.BLOCK, matcher.decisionFor("example.com"))
        assertEquals(DomainRuleAction.ALLOW, matcher.decisionFor("child.example.com"))
    }

    @Test
    fun lastDuplicateDomainAndScopeWinsAfterNormalization() {
        val matcher = matcher(
            UserDomainRule("BÜCHER.example.", DomainRuleAction.ALLOW, includeSubdomains = true),
            UserDomainRule("xn--bcher-kva.example", DomainRuleAction.BLOCK, includeSubdomains = true)
        )

        assertEquals(DomainRuleAction.BLOCK, matcher.decisionFor("child.bücher.example"))
    }

    private fun matcher(vararg rules: UserDomainRule) = UserDomainRuleMatcher(rules.asIterable())
}
