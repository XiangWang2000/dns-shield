package io.github.xiangwang2000.dnsshield.blocking

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BuiltInDomainMatcherTest {
    private val matcher = BuiltInDomainMatcher()

    @Test
    fun blocksExactDomains() {
        assertTrue(matcher.shouldBlock("doubleclick.net"))
        assertTrue(matcher.shouldBlock("PAGEAD2.GOOGLESYNDICATION.COM"))
    }

    @Test
    fun blocksSubdomainsBySuffix() {
        assertTrue(matcher.shouldBlock("securepubads.g.doubleclick.net"))
        assertTrue(matcher.shouldBlock("cdn.appsflyer.com"))
    }

    @Test
    fun preservesContainsRules() {
        assertTrue(matcher.shouldBlock("api.amazon-adsystem.example"))
        assertTrue(matcher.shouldBlock("telemetry-endpoint.example"))
    }

    @Test
    fun blocksExactDomainLabels() {
        assertTrue(matcher.shouldBlock("ads.example.com"))
        assertTrue(matcher.shouldBlock("api.tracker.example.com"))
    }

    @Test
    fun ignoresBlankUnknownAndOrdinaryDomains() {
        assertFalse(matcher.shouldBlock(""))
        assertFalse(matcher.shouldBlock(" Unknown "))
        assertFalse(matcher.shouldBlock("github.com"))
        assertFalse(matcher.shouldBlock("example.com"))
    }
}
