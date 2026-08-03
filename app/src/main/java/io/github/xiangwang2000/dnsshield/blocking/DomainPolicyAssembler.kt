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
 * loaded and validated successfully. Recoverable loading failures reject the optional blocklist
 * and preserve the built-in matcher instead of disabling DNS protection.
 */
object DomainPolicyAssembler {
    fun assemble(
        compiledBlocklistFile: File? = null,
        allowlist: DomainAllowlist = DomainAllowlist.NONE,
        builtInMatcher: DomainMatcher = BuiltInDomainMatcher(),
        loadCompiledBlocklist: (File) -> CompiledBlocklist = CompiledBlocklistLoader::fromFile
    ): DomainPolicyAssembly {
        val blockers = mutableListOf(builtInMatcher)

        if (compiledBlocklistFile == null) {
            return DomainPolicyAssembly(
                matcher = CompositeDomainMatcher(allowlist, blockers),
                compiledBlocklistStatus = CompiledBlocklistStatus.NotConfigured
            )
        }

        val status = try {
            val compiledBlocklist = loadCompiledBlocklist(compiledBlocklistFile)
            compiledBlocklist.validateSorted()
            blockers += CompiledBlocklistMatcher(compiledBlocklist)
            CompiledBlocklistStatus.Loaded(compiledBlocklist.entryCount)
        } catch (exception: Exception) {
            CompiledBlocklistStatus.Rejected(
                exception.message?.takeIf(String::isNotBlank)
                    ?: exception.javaClass.simpleName
            )
        }

        return DomainPolicyAssembly(
            matcher = CompositeDomainMatcher(allowlist, blockers),
            compiledBlocklistStatus = status
        )
    }
}
