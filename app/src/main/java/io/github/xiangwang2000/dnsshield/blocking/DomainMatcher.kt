package io.github.xiangwang2000.dnsshield.blocking

/**
 * Decides whether a normalized DNS domain should be blocked.
 *
 * Implementations must be side-effect free so they can be composed, cached,
 * and tested independently from the VPN service lifecycle.
 */
fun interface DomainMatcher {
    fun shouldBlock(domain: String): Boolean
}

/**
 * Preserves the blocking behavior that currently lives in DnsVpnService.
 *
 * This is intentionally a behavior-preserving extraction. The broad contains
 * rules remain unchanged for now and can be tightened in a later policy change.
 */
class BuiltInDomainMatcher : DomainMatcher {
    private val exactBlocks = setOf(
        "doubleclick.net",
        "admob.com",
        "pagead2.googlesyndication.com",
        "googleads.g.doubleclick.net",
        "analytics.google.com",
        "crashlytics.com"
    )

    private val suffixBlocks = listOf(
        ".doubleclick.net",
        ".admob.com",
        ".analytics.google.com",
        ".adnxs.com",
        ".adcolony.com",
        ".adservice.google.com",
        ".scorecardresearch.com",
        ".hotjar.com",
        ".telemetry.mozilla.org",
        ".adjust.com",
        ".appsflyer.com"
    )

    private val containsBlocks = listOf(
        "adservice",
        "adsystem",
        "googleads",
        "pagead",
        "amazon-adsystem",
        "telemetry-",
        "analytics-"
    )

    private val exactBlockedLabels = setOf(
        "ads",
        "tracker",
        "telemetry",
        "analytics",
        "crashlytics"
    )

    override fun shouldBlock(domain: String): Boolean {
        val normalized = normalize(domain)
        if (normalized.isEmpty() || normalized == "unknown") return false

        if (normalized in exactBlocks) return true
        if (suffixBlocks.any(normalized::endsWith)) return true
        if (containsBlocks.any(normalized::contains)) return true

        return normalized
            .split('.')
            .any(exactBlockedLabels::contains)
    }

    internal fun normalize(domain: String): String = domain.lowercase().trim()
}
