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
        "1.1.1.1" to "https://cloudflare-dns.com/dns-query",
        "1.0.0.1" to "https://cloudflare-dns.com/dns-query",
        "94.140.14.14" to "https://dns.adguard-dns.com/dns-query",
        "94.140.15.15" to "https://dns.adguard-dns.com/dns-query",
        "9.9.9.9" to "https://dns.quad9.net/dns-query",
        "149.112.112.112" to "https://dns.quad9.net/dns-query"
    )

    val builtInBootstrapAddresses = mapOf(
        "dns.google" to listOf("8.8.8.8", "8.8.4.4"),
        "cloudflare-dns.com" to listOf("1.1.1.1", "1.0.0.1"),
        "dns.adguard-dns.com" to listOf("94.140.14.14", "94.140.15.15"),
        "dns.quad9.net" to listOf("9.9.9.9", "149.112.112.112")
    )

    fun defaultUrlForIp(ip: String): String? = defaultUrlByIp[ip]

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
        val explicitAddresses = parseBootstrapIpv4Addresses(configuredBootstrapIps)
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
        val bootstrapAddresses = parseBootstrapIpv4Addresses(bootstrap)
            ?: return "Bootstrap 僅接受逗號分隔的 IPv4 位址"
        if (strict && !isIpLiteral(parsedUrl.host) && bootstrapAddresses.isEmpty()) {
            return "僅加密模式的自訂 DoH 主機名稱必須設定 Bootstrap IPv4 位址"
        }
        return null
    }

    fun parseBootstrapIpv4Addresses(value: String?): List<String>? {
        val text = value?.trim().orEmpty()
        if (text.isEmpty()) return emptyList()
        val addresses = text.split(Regex("[,\\s]+")).filter(String::isNotEmpty)
        return addresses.takeIf { it.all(::isIpv4Literal) }?.distinct()
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
    val parts = value.split('.')
    return parts.size == 4 && parts.all { part ->
        part.isNotEmpty() && part.length <= 3 && part.all(Char::isDigit) &&
            part.toIntOrNull()?.let { it in 0..255 } == true
    }
}

internal fun isIpLiteral(hostname: String): Boolean =
    isIpv4Literal(hostname) || (hostname.contains(':') && hostname.matches(Regex("[0-9a-fA-F:%.]+")))
