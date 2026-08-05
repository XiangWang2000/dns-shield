package io.github.xiangwang2000.dnsshield.blocking

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ParentDomainMatcherTest {
    @Test
    fun exactMatchShortCircuitsWithoutResolvingBoundary() {
        var resolverCalls = 0
        val matcher = ParentDomainMatcher(
            exactMatcher = DomainMatcher { it == "ads.example.com" },
            registrableDomainResolver = RegistrableDomainResolver {
                resolverCalls++
                "example.com"
            }
        )

        assertTrue(matcher.shouldBlock(" ADS.EXAMPLE.COM "))
        assertEquals(0, resolverCalls)
    }

    @Test
    fun checksNearestParentsThroughRegistrableDomain() {
        val candidates = mutableListOf<String>()
        val matcher = ParentDomainMatcher(
            exactMatcher = DomainMatcher { candidate ->
                candidates += candidate
                candidate == "example.co.uk"
            },
            registrableDomainResolver = RegistrableDomainResolver { "example.co.uk" }
        )

        assertTrue(matcher.shouldBlock("a.b.example.co.uk"))
        assertEquals(
            listOf("a.b.example.co.uk", "b.example.co.uk", "example.co.uk"),
            candidates
        )
    }

    @Test
    fun neverChecksPublicSuffixAboveRegistrableBoundary() {
        val candidates = mutableListOf<String>()
        val matcher = ParentDomainMatcher(
            exactMatcher = DomainMatcher { candidate ->
                candidates += candidate
                candidate == "co.uk" || candidate == "uk"
            },
            registrableDomainResolver = RegistrableDomainResolver { "example.co.uk" }
        )

        assertFalse(matcher.shouldBlock("ads.example.co.uk"))
        assertEquals(listOf("ads.example.co.uk", "example.co.uk"), candidates)
    }

    @Test
    fun privateSuffixBoundaryIsAlsoRespected() {
        val candidates = mutableListOf<String>()
        val matcher = ParentDomainMatcher(
            exactMatcher = DomainMatcher { candidate ->
                candidates += candidate
                candidate == "github.io"
            },
            registrableDomainResolver = RegistrableDomainResolver { "tenant.github.io" }
        )

        assertFalse(matcher.shouldBlock("ads.tenant.github.io"))
        assertEquals(listOf("ads.tenant.github.io", "tenant.github.io"), candidates)
    }

    @Test
    fun missingBoundaryKeepsMatchingExactOnly() {
        val candidates = mutableListOf<String>()
        val matcher = ParentDomainMatcher(
            exactMatcher = DomainMatcher { candidate ->
                candidates += candidate
                candidate == "example.com"
            },
            registrableDomainResolver = RegistrableDomainResolver { null }
        )

        assertFalse(matcher.shouldBlock("ads.example.com"))
        assertEquals(listOf("ads.example.com"), candidates)
    }

    @Test
    fun unrelatedBoundaryKeepsMatchingExactOnly() {
        val candidates = mutableListOf<String>()
        val matcher = ParentDomainMatcher(
            exactMatcher = DomainMatcher { candidate ->
                candidates += candidate
                candidate == "example.com"
            },
            registrableDomainResolver = RegistrableDomainResolver { "other.com" }
        )

        assertFalse(matcher.shouldBlock("ads.example.com"))
        assertEquals(listOf("ads.example.com"), candidates)
    }

    @Test
    fun lookalikeDomainCannotUseSuffixWithoutLabelBoundary() {
        val candidates = mutableListOf<String>()
        val matcher = ParentDomainMatcher(
            exactMatcher = DomainMatcher { candidate ->
                candidates += candidate
                candidate == "example.com"
            },
            registrableDomainResolver = RegistrableDomainResolver { "example.com" }
        )

        assertFalse(matcher.shouldBlock("lookalike-example.com"))
        assertEquals(listOf("lookalike-example.com"), candidates)
    }

    @Test
    fun normalizesQueryAndResolverBoundary() {
        val candidates = mutableListOf<String>()
        var resolverInput = ""
        val matcher = ParentDomainMatcher(
            exactMatcher = DomainMatcher { candidate ->
                candidates += candidate
                candidate == "example.com"
            },
            registrableDomainResolver = RegistrableDomainResolver { domain ->
                resolverInput = domain
                " EXAMPLE.COM "
            }
        )

        assertTrue(matcher.shouldBlock(" ADS.EXAMPLE.COM "))
        assertEquals("ads.example.com", resolverInput)
        assertEquals(listOf("ads.example.com", "example.com"), candidates)
    }

    @Test
    fun registrableDomainIsNotCheckedTwice() {
        val candidates = mutableListOf<String>()
        val matcher = ParentDomainMatcher(
            exactMatcher = DomainMatcher { candidate ->
                candidates += candidate
                false
            },
            registrableDomainResolver = RegistrableDomainResolver { "example.com" }
        )

        assertFalse(matcher.shouldBlock("example.com"))
        assertEquals(listOf("example.com"), candidates)
    }

    @Test
    fun unusableDomainsDoNotInvokeDependencies() {
        var calls = 0
        val matcher = ParentDomainMatcher(
            exactMatcher = DomainMatcher {
                calls++
                true
            },
            registrableDomainResolver = RegistrableDomainResolver {
                calls++
                "example.com"
            }
        )

        assertFalse(matcher.shouldBlock(""))
        assertFalse(matcher.shouldBlock(" UNKNOWN "))
        assertFalse(matcher.shouldBlock(".example.com"))
        assertFalse(matcher.shouldBlock("example.com."))
        assertFalse(matcher.shouldBlock("a..example.com"))
        assertEquals(0, calls)
    }
}
