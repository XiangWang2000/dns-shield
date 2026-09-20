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
        registrableDomainResolverProvider: () -> RegistrableDomainResolver? = { null }
    ): DomainPolicyAssembly {
        val activeFile = activeBlocklistFile(filesDirectory)
        val privateBlocklistFile = activeFile.takeIf { it.exists() }
        return DomainPolicyAssembler.assemble(
            compiledBlocklistFile = privateBlocklistFile,
            allowlist = allowlist,
            userRules = userRules,
            builtInMatcher = builtInMatcher,
            loadCompiledBlocklist = loadCompiledBlocklist,
            compiledBlocklistProvider = loadBundledBlocklist.takeIf {
                privateBlocklistFile == null
            },
            registrableDomainResolverProvider = registrableDomainResolverProvider
        )
    }
}
