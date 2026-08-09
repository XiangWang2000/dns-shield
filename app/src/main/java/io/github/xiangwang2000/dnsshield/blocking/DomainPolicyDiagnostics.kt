package io.github.xiangwang2000.dnsshield.blocking

/** Formats the service diagnostic emitted after publishing a runtime policy assembly. */
internal object DomainPolicyDiagnostics {
    fun message(status: CompiledBlocklistStatus): String = when (status) {
        CompiledBlocklistStatus.NotConfigured ->
            "[攔截規則] 未設定 compiled blocklist，使用內建規則"

        is CompiledBlocklistStatus.Loaded ->
            "[攔截規則] 已載入 compiled blocklist：${status.entryCount} 筆"

        is CompiledBlocklistStatus.Rejected ->
            "[攔截規則] compiled blocklist 無法載入，已回退內建規則：${status.reason}"
    }
}
