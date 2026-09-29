package io.github.xiangwang2000.dnsshield.blocking

import java.io.File

/**
 * Resolves an app-private active compiled blocklist or a caller-supplied bundled default.
 *
 * The stable path is `<filesDir>/blocklists/active.bin`. A missing file means the optional
 * blocklist selects the bundled provider when one is configured. Existing empty, malformed,
 * directory, or unreadable private inputs are passed to [DomainPolicyAssembler] so they are
 * reported as rejected instead of being hidden.
 */
object RuntimeDomainPolicy {
    const val BLOCKLIST_DIRECTORY_NAME = "blocklists"
    const val ACTIVE_BLOCKLIST_FILE_NAME = "active.bin"

    fun activeBlocklistFile(filesDirectory: File): File =
        File(File(filesDirectory, BLOCKLIST_DIRECTORY_NAME), ACTIVE_BLOCKLIST_FILE_NAME)

    fun assemble(
        filesDirectory: File,
        allowlist: DomainAllowlist = DomainAllowlist.NONE,
        userRules: Iterable<UserDomainRule> = emptyList(),
        builtInMatcher: DomainMatcher = BuiltInDomainMatcher(),
        loadCompiledBlocklist: (File) -> CompiledBlocklist = CompiledBlocklistLoader::fromFile,
        loadBundledBlocklist: (() -> CompiledBlocklist)? = null,
        bundledSourceMetadata: RuleSourceMetadata? = null,
        registrableDomainResolverProvider: () -> RegistrableDomainResolver? = { null }
    ): DomainPolicyAssembly {
        val activeFile = activeBlocklistFile(filesDirectory)
        val privateBlocklistFile = activeFile.takeIf { it.exists() }

        fun assembleBundled(): DomainPolicyAssembly = DomainPolicyAssembler.assemble(
            allowlist = allowlist,
            userRules = userRules,
            builtInMatcher = builtInMatcher,
            compiledBlocklistProvider = loadBundledBlocklist,
            registrableDomainResolverProvider = registrableDomainResolverProvider
        )

        fun bundledStatus(
            assembly: DomainPolicyAssembly,
            degradationReason: String? = null
        ): RulePolicyStatus = if (assembly.compiledBlocklistStatus is CompiledBlocklistStatus.Loaded) {
            RulePolicyStatus(
                source = RuleBlocklistSource.APK_BUNDLED,
                sourceName = bundledSourceMetadata?.name ?: "APK 內建清單",
                sourceRevision = bundledSourceMetadata?.revision,
                sourceDate = bundledSourceMetadata?.sourceDate,
                entryCount = assembly.compiledBlocklistStatus.entryCount,
                validation = RuleBlocklistValidation.APK_VERIFIED,
                degradationReason = degradationReason
            )
        } else {
            RulePolicyStatus(
                degradationReason = degradationReason
                    ?: (assembly.compiledBlocklistStatus as? CompiledBlocklistStatus.Rejected)
                        ?.reason
            )
        }

        val privateAssembly = privateBlocklistFile?.let { file ->
            DomainPolicyAssembler.assemble(
                compiledBlocklistFile = file,
                allowlist = allowlist,
                builtInMatcher = builtInMatcher,
                loadCompiledBlocklist = loadCompiledBlocklist,
                registrableDomainResolverProvider = registrableDomainResolverProvider
            )
        }

        if (privateAssembly != null) {
            when (val status = privateAssembly.compiledBlocklistStatus) {
                is CompiledBlocklistStatus.Loaded -> return privateAssembly.copy(
                    displayStatus = RulePolicyStatus(
                        source = RuleBlocklistSource.PRIVATE_OVERRIDE,
                        sourceName = "App 私有 override",
                        entryCount = status.entryCount,
                        validation = RuleBlocklistValidation.PRIVATE_STRUCTURE_CHECKED
                    )
                )
                is CompiledBlocklistStatus.Rejected -> {
                    if (loadBundledBlocklist == null) return privateAssembly.copy(
                        displayStatus = RulePolicyStatus(
                        degradationReason = "本機覆寫檔未通過檢查；目前僅使用內建規則：${status.reason}"
                        )
                    )

                    val bundledAssembly = assembleBundled()
                    return if (bundledAssembly.compiledBlocklistStatus is CompiledBlocklistStatus.Loaded) {
                        bundledAssembly.copy(
                            displayStatus = bundledStatus(
                                bundledAssembly,
                                "本機覆寫檔未通過檢查，已改用 APK 清單：${status.reason}"
                            )
                        )
                    } else {
                        val bundledFailure =
                            (bundledAssembly.compiledBlocklistStatus as? CompiledBlocklistStatus.Rejected)
                                ?.reason ?: "APK 清單未設定"
                        bundledAssembly.copy(
                            compiledBlocklistStatus = CompiledBlocklistStatus.Rejected(
                                "本機 override 驗證失敗：${status.reason}；APK 清單回退失敗：$bundledFailure"
                            ),
                            displayStatus = bundledStatus(
                                bundledAssembly,
                                "本機覆寫檔未通過檢查：${status.reason}；" +
                                    "APK 清單回退失敗：$bundledFailure；目前僅使用內建規則。"
                            )
                        )
                    }
                }
                CompiledBlocklistStatus.NotConfigured -> Unit
            }
        }

        if (loadBundledBlocklist != null) {
            val bundledAssembly = assembleBundled()
            return bundledAssembly.copy(displayStatus = bundledStatus(bundledAssembly))
        }

        return DomainPolicyAssembler.assemble(
            allowlist = allowlist,
            builtInMatcher = builtInMatcher
        )
    }
}
