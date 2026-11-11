package io.github.xiangwang2000.dnsshield.service

import io.github.xiangwang2000.dnsshield.data.DnsServer
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

internal data class DnsDohEndpoint(
    val url: String,
    val hostname: String,
    val bootstrapAddresses: List<String>,
    val isCustom: Boolean
) {
    val canResolveHost: Boolean
        get() = isIpLiteral(hostname) || bootstrapAddresses.isNotEmpty()
}

internal object DohEndpointConfiguration {
    const val STRICT_MODE_REQUIRES_ENDPOINT_ERROR =
        "僅加密模式至少需要一個可用的 HTTPS DoH 端點"

    private val defaultUrlByIp = mapOf(
        "8.8.8.8" to "https://dns.google/dns-query",
        "8.8.4.4" to "https://dns.google/dns-query",
        "2001:4860:4860::8888" to "https://dns.google/dns-query",
        "2001:4860:4860::8844" to "https://dns.google/dns-query",
        "1.1.1.1" to "https://cloudflare-dns.com/dns-query",
        "1.0.0.1" to "https://cloudflare-dns.com/dns-query",
        "2606:4700:4700::1111" to "https://cloudflare-dns.com/dns-query",
        "2606:4700:4700::1001" to "https://cloudflare-dns.com/dns-query",
        "94.140.14.14" to "https://dns.adguard-dns.com/dns-query",
        "94.140.15.15" to "https://dns.adguard-dns.com/dns-query",
        "2a10:50c0::ad1:ff" to "https://dns.adguard-dns.com/dns-query",
        "2a10:50c0::ad2:ff" to "https://dns.adguard-dns.com/dns-query",
        "9.9.9.9" to "https://dns.quad9.net/dns-query",
        "149.112.112.112" to "https://dns.quad9.net/dns-query",
        "2620:fe::fe" to "https://dns.quad9.net/dns-query",
        "2620:fe::9" to "https://dns.quad9.net/dns-query"
    )

    val builtInBootstrapAddresses = mapOf(
        "dns.google" to listOf(
            "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"
        ),
        "cloudflare-dns.com" to listOf(
            "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"
        ),
        "dns.adguard-dns.com" to listOf(
            "94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"
        ),
        "dns.quad9.net" to listOf(
            "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"
        )
    )

    fun defaultUrlForIp(ip: String): String? =
        defaultUrlByIp[ip] ?: IpAddressLiteral.parse(ip)?.normalized?.let(defaultUrlByIp::get)

    fun endpoints(server: DnsServer): List<DnsDohEndpoint> = endpoints(
        server.primaryIp,
        server.secondaryIp,
        server.primaryDohUrl,
        server.primaryDohBootstrapIps,
        server.secondaryDohUrl,
        server.secondaryDohBootstrapIps
    )

    fun endpoints(
        primaryIp: String,
        secondaryIp: String?,
        primaryDohUrl: String?,
        primaryDohBootstrapIps: String?,
        secondaryDohUrl: String?,
        secondaryDohBootstrapIps: String?
    ): List<DnsDohEndpoint> = listOfNotNull(
        endpoint(primaryDohUrl, primaryDohBootstrapIps, primaryIp),
        endpoint(secondaryDohUrl, secondaryDohBootstrapIps, secondaryIp.orEmpty())
    )

    fun hasUsableEncryptedEndpoint(server: DnsServer): Boolean =
        endpoints(server).any { it.canResolveHost }

    fun hasUsableEncryptedEndpoint(
        primaryIp: String,
        secondaryIp: String?,
        primaryDohUrl: String?,
        primaryDohBootstrapIps: String?,
        secondaryDohUrl: String?,
        secondaryDohBootstrapIps: String?
    ): Boolean = endpoints(
        primaryIp,
        secondaryIp,
        primaryDohUrl,
        primaryDohBootstrapIps,
        secondaryDohUrl,
        secondaryDohBootstrapIps
    ).any { it.canResolveHost }

    fun endpoint(
        configuredUrl: String?,
        configuredBootstrapIps: String?,
        resolverIp: String
    ): DnsDohEndpoint? {
        val isCustom = !configuredUrl.isNullOrBlank()
        val url = configuredUrl?.trim()?.takeIf(String::isNotEmpty)
            ?: defaultUrlForIp(resolverIp)
            ?: return null
        val parsedUrl = parseHttpsUrl(url) ?: return null
        val explicitAddresses = parseBootstrapIpAddresses(configuredBootstrapIps)
            ?: return null
        val addresses = if (isCustom) {
            explicitAddresses
        } else {
            builtInBootstrapAddresses[parsedUrl.host].orEmpty()
        }
        return DnsDohEndpoint(url, parsedUrl.host, addresses, isCustom)
    }

    fun validationError(
        configuredUrl: String,
        configuredBootstrapIps: String,
        strict: Boolean
    ): String? {
        val url = configuredUrl.trim()
        val bootstrap = configuredBootstrapIps.trim()
        if (url.isEmpty()) {
            return if (bootstrap.isEmpty()) null else "Bootstrap 位址需要搭配 DoH URL"
        }

        val parsedUrl = parseHttpsUrl(url)
            ?: return "DoH URL 必須是有效的 HTTPS 網址，且不可含帳密或片段"
        val bootstrapAddresses = parseBootstrapIpAddresses(bootstrap)
            ?: return "Bootstrap 請輸入 IPv4 或 IPv6 位址，以逗號或空白分隔；不支援中括號或範圍 ID。"
        if (strict && !isIpLiteral(parsedUrl.host) && bootstrapAddresses.isEmpty()) {
            return "僅加密模式下，自訂 DoH 主機名稱需要 Bootstrap IP 位址。"
        }
        return null
    }

    fun parseBootstrapIpAddresses(value: String?): List<String>? {
        val text = value?.trim().orEmpty()
        if (text.isEmpty()) return emptyList()
        val addresses = text.split(Regex("[,\\s]+")).filter(String::isNotEmpty)
        val normalized = addresses.map { IpAddressLiteral.parse(it)?.normalized ?: return null }
        return normalized.distinct()
    }

    private fun parseHttpsUrl(value: String): HttpUrl? {
        val parsed = value.toHttpUrlOrNull() ?: return null
        if (parsed.scheme != "https" || parsed.username.isNotEmpty() ||
            parsed.password.isNotEmpty() || parsed.fragment != null
        ) {
            return null
        }
        return parsed
    }
}

internal fun isIpv4Literal(value: String): Boolean {
    return IpAddressLiteral.isIpv4(value)
}

internal fun isIpLiteral(value: String): Boolean = IpAddressLiteral.parse(value) != null
