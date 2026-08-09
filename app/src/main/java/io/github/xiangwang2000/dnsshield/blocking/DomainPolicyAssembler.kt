package io.github.xiangwang2000.dnsshield.blocking

import java.io.File

/** Describes whether an optional compiled blocklist participated in the assembled policy. */
sealed class CompiledBlocklistStatus {
    data object NotConfigured : CompiledBlocklistStatus()
    data class Loaded(val entryCount: Int) : CompiledBlocklistStatus() {
        init {
            require(entryCount >= 0) { "Compiled blocklist entry count must be non-negative" }
        }
    }
    data class Rejected(val reason: String) : CompiledBlocklistStatus() {
        init {
            require(reason.isNotBlank()) { "Compiled blocklist rejection reason must not be blank" }
        }
    }
}

/** Pure policy assembly result. Runtime callers may log [compiledBlocklistStatus]. */
data class DomainPolicyAssembly(
    val matcher: DomainMatcher,
    val compiledBlocklistStatus: CompiledBlocklistStatus
)

/**
 * Assembles allowlist-first blocking policy without depending on the VPN lifecycle.
 *
 * Built-in blocking is always present. A configured compiled blocklist is added only after it is
 * loaded and validated successfully. When a registrable-domain resolver is available, only the
 * compiled blocklist matcher is extended through [ParentDomainMatcher]; built-in and exact
 * allowlist semantics remain unchanged.
 *
 * The resolver provider is invoked only after a compiled blocklist has loaded and validated. A
 * recoverable resolver-provider failure keeps the validated compiled matcher exact-only instead of
 * dropping it or disabling built-in protection.
 */
object DomainPolicyAssembler {
    fun assemble(
        compiledBlocklistFile: File? = null,
        allowlist: DomainAllowlist = DomainAllowlist.NONE,
        builtInMatcher: DomainMatcher = BuiltInDomainMatcher(),
        loadCompiledBlocklist: (File) -> CompiledBlocklist = CompiledBlocklistLoader::fromFile,
        registrableDomainResolverProvider: () -> RegistrableDomainResolver? = { null }
    ): DomainPolicyAssembly {
        val blockers = mutableListOf(builtInMatcher)

        if (compiledBlocklistFile == null) {
            return DomainPolicyAssembly(
                matcher = CompositeDomainMatcher(allowlist, blockers),
                compiledBlocklistStatus = CompiledBlocklistStatus.NotConfigured
            )
        }

        val compiledBlocklist = try {
            val loaded = loadCompiledBlocklist(compiledBlocklistFile)
            loaded.validateSorted()
            loaded
        } catch (exception: Exception) {
            return DomainPolicyAssembly(
                matcher = CompositeDomainMatcher(allowlist, blockers),
                compiledBlocklistStatus = CompiledBlocklistStatus.Rejected(
                    exception.message?.takeIf(String::isNotBlank)
                        ?: exception.javaClass.simpleName
                )
            )
        }

        val exactCompiledMatcher = CompiledBlocklistMatcher(compiledBlocklist)
        val compiledMatcher = try {
            registrableDomainResolverProvider()?.let { resolver ->
                ParentDomainMatcher(exactCompiledMatcher, resolver)
            } ?: exactCompiledMatcher
        } catch (_: Exception) {
            exactCompiledMatcher
        }
        blockers += compiledMatcher

        return DomainPolicyAssembly(
            matcher = CompositeDomainMatcher(allowlist, blockers),
            compiledBlocklistStatus = CompiledBlocklistStatus.Loaded(compiledBlocklist.entryCount)
        )
    }
}
