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
    fun blocksKnownAdServiceAndAmazonAdsSystemDomains() {
        assertTrue(matcher.shouldBlock("adservice.google.com"))
        assertTrue(matcher.shouldBlock("api.adservice.google.com"))
        assertTrue(matcher.shouldBlock("amazon-adsystem.com"))
        assertTrue(matcher.shouldBlock("api.amazon-adsystem.com"))
        assertTrue(matcher.shouldBlock("cdn.api.amazon-adsystem.com"))
        assertFalse(matcher.shouldBlock("api.amazon-adsystem.example"))
    }

    @Test
    fun blocksExactDomainLabels() {
        assertTrue(matcher.shouldBlock("ads.example.com"))
        assertTrue(matcher.shouldBlock("api.tracker.example.com"))
        assertTrue(matcher.shouldBlock(".telemetry..example.com"))
        assertTrue(matcher.shouldBlock("example.com.crashlytics"))
    }

    @Test
    fun doesNotBlockPartialLabels() {
        assertFalse(matcher.shouldBlock("bads.example.com"))
        assertFalse(matcher.shouldBlock("trackerx.example.com"))
        assertFalse(matcher.shouldBlock("myanalytics.example.com"))
        assertFalse(matcher.shouldBlock("crashlytics2.example.com"))
        assertFalse(matcher.shouldBlock("mypageadmin.example.com"))
        assertFalse(matcher.shouldBlock("analytics-tooling.example.org"))
        assertFalse(matcher.shouldBlock("telemetry-workshop.example.edu"))
    }

    @Test
    fun ignoresBlankUnknownAndOrdinaryDomains() {
        assertFalse(matcher.shouldBlock(""))
        assertFalse(matcher.shouldBlock(" Unknown "))
        assertFalse(matcher.shouldBlock("github.com"))
        assertFalse(matcher.shouldBlock("example.com"))
    }
}
