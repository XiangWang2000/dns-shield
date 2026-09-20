package io.github.xiangwang2000.dnsshield.service

enum class DnsDecision {
    ALLOW,
    BLOCK
}

enum class DnsDecisionReason {
    USER_RULE,
    PROTECTION_LIST
}

data class DnsDecisionEvent(
    val id: Long,
    val domain: String,
    val decision: DnsDecision,
    val reason: DnsDecisionReason,
    val occurredAtMillis: Long
)
