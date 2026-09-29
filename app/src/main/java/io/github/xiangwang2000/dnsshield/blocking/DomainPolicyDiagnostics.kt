package io.github.xiangwang2000.dnsshield.blocking

enum class RuleBlocklistSource {
    NOT_LOADED,
    BUILT_IN,
    APK_BUNDLED,
    PRIVATE_OVERRIDE
}

enum class RuleBlocklistValidation {
    BUILT_IN,
    APK_VERIFIED,
    PRIVATE_STRUCTURE_CHECKED
}

data class RuleSourceMetadata(
    val name: String,
    val revision: String?,
    val sourceDate: String?
)

data class RulePolicyStatus(
    val source: RuleBlocklistSource = RuleBlocklistSource.BUILT_IN,
    val sourceName: String = "",
    val sourceRevision: String? = null,
    val sourceDate: String? = null,
    val entryCount: Int? = null,
    val validation: RuleBlocklistValidation = RuleBlocklistValidation.BUILT_IN,
    val degradationReason: String? = null,
    val publicSuffixStatus: PublicSuffixResolverStatus = PublicSuffixResolverStatus.NotLoaded,
    val reloadError: String? = null
) {
    companion object {
        val NotLoaded = RulePolicyStatus(source = RuleBlocklistSource.NOT_LOADED)
    }
}

/** Formats the service diagnostic emitted after publishing a runtime policy assembly. */
internal object DomainPolicyDiagnostics {
    fun details(status: RulePolicyStatus): List<String> = buildList {
        when (status.source) {
            RuleBlocklistSource.NOT_LOADED -> {
                add("規則來源：尚未載入")
                status.reloadError?.let { add("規則重新載入失敗：$it") }
                return@buildList
            }
            RuleBlocklistSource.BUILT_IN -> add("規則來源：內建規則")
            RuleBlocklistSource.APK_BUNDLED -> add("規則來源：APK 內建清單（${status.sourceName}）")
            RuleBlocklistSource.PRIVATE_OVERRIDE -> add("規則來源：App 私有覆寫檔")
        }
        add("來源 revision：${status.sourceRevision ?: "未提供"}")
        add("來源日期：${status.sourceDate ?: "未知"}")
        status.entryCount?.let { add("規則數：${it} 筆") }
        add(
            "驗證狀態：" + when (status.validation) {
                RuleBlocklistValidation.BUILT_IN -> "使用內建規則"
                RuleBlocklistValidation.APK_VERIFIED -> "APK 清單完整性驗證通過"
                RuleBlocklistValidation.PRIVATE_STRUCTURE_CHECKED ->
                    "格式與排序檢查通過；來源身分未驗證"
            }
        )
        status.degradationReason?.let { add("降級原因：$it") }
        when (val suffix = status.publicSuffixStatus) {
            PublicSuffixResolverStatus.NotLoaded -> Unit
            is PublicSuffixResolverStatus.Loaded -> add(
                "Public Suffix List：已載入（${suffix.exactRules} 條一般、" +
                    "${suffix.wildcardRules} 條萬用、${suffix.exceptionRules} 條例外規則）"
            )
            is PublicSuffixResolverStatus.Rejected -> add(
                "Public Suffix List 載入失敗；已降級為精確網域比對：${suffix.reason}"
            )
        }
        status.reloadError?.let { add("規則重新載入失敗，保留前一版：$it") }
    }

    fun message(status: RulePolicyStatus): String = details(status).joinToString("；")

    fun message(status: CompiledBlocklistStatus): String = when (status) {
        CompiledBlocklistStatus.NotConfigured ->
            "[攔截規則] 未設定 compiled blocklist，使用內建規則"

        is CompiledBlocklistStatus.Loaded ->
            "[攔截規則] 已載入 compiled blocklist：${status.entryCount} 筆"

        is CompiledBlocklistStatus.Rejected ->
            "[攔截規則] compiled blocklist 無法載入，已回退內建規則：${status.reason}"
    }
}
