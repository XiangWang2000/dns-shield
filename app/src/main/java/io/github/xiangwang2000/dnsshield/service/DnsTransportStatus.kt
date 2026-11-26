package io.github.xiangwang2000.dnsshield.service

/**
 * Structured upstream transport state.
 *
 * The UI selects both its label and its colour from this enum, so display wording can change
 * without silently changing colour semantics.
 */
enum class DnsTransportStatus {
    IDLE,
    SETTINGS_UPDATED,
    ENCRYPTED_HTTPS,
    PLAINTEXT_UDP,
    PLAINTEXT_TCP,
    SYSTEM,
    UNAVAILABLE_SYSTEM,
    UNAVAILABLE_FALLBACK,
    UNAVAILABLE_STRICT
}

fun DnsTransportStatus.displayText(): String = when (this) {
    DnsTransportStatus.IDLE -> "尚無上游查詢"
    DnsTransportStatus.SETTINGS_UPDATED -> "設定已更新，等待下一次查詢"
    DnsTransportStatus.ENCRYPTED_HTTPS -> "DoH 加密"
    DnsTransportStatus.PLAINTEXT_UDP -> "UDP/53 明文降級"
    DnsTransportStatus.PLAINTEXT_TCP -> "TCP/53 明文降級"
    DnsTransportStatus.SYSTEM -> "系統 DNS"
    DnsTransportStatus.UNAVAILABLE_SYSTEM -> "系統 DNS 無法解析 · SERVFAIL"
    DnsTransportStatus.UNAVAILABLE_FALLBACK -> "上游不可用 · SERVFAIL"
    DnsTransportStatus.UNAVAILABLE_STRICT -> "僅加密 · DoH 不可用 · SERVFAIL"
}
