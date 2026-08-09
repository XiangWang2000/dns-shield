package io.github.xiangwang2000.dnsshield.blocking

import java.io.File

/**
 * Resolves the optional active compiled blocklist from the app-private files directory.
 *
 * The stable path is `<filesDir>/blocklists/active.bin`. A missing file means the optional
 * blocklist is not configured. Existing empty, malformed, directory, or unreadable inputs are
 * passed to [DomainPolicyAssembler] so they are reported as rejected instead of being hidden.
 */
object RuntimeDomainPolicy {
    const val BLOCKLIST_DIRECTORY_NAME = "blocklists"
    const val ACTIVE_BLOCKLIST_FILE_NAME = "active.bin"

    fun activeBlocklistFile(filesDirectory: File): File =
        File(File(filesDirectory, BLOCKLIST_DIRECTORY_NAME), ACTIVE_BLOCKLIST_FILE_NAME)

    fun assemble(
        filesDirectory: File,
        allowlist: DomainAllowlist = DomainAllowlist.NONE,
        builtInMatcher: DomainMatcher = BuiltInDomainMatcher(),
        loadCompiledBlocklist: (File) -> CompiledBlocklist = CompiledBlocklistLoader::fromFile,
        registrableDomainResolverProvider: () -> RegistrableDomainResolver? = { null }
    ): DomainPolicyAssembly {
        val activeFile = activeBlocklistFile(filesDirectory)
        return DomainPolicyAssembler.assemble(
            compiledBlocklistFile = activeFile.takeIf { it.exists() },
            allowlist = allowlist,
            builtInMatcher = builtInMatcher,
            loadCompiledBlocklist = loadCompiledBlocklist,
            registrableDomainResolverProvider = registrableDomainResolverProvider
        )
    }
}
