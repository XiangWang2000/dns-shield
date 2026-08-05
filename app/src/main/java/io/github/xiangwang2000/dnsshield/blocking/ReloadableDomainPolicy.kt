package io.github.xiangwang2000.dnsshield.blocking

import java.util.concurrent.atomic.AtomicReference

/**
 * Publishes complete domain-policy assemblies atomically to concurrent DNS readers.
 *
 * Readers always observe either the previous assembly or the replacement assembly. Installers are
 * serialized, and [beforePublish] runs while the previous assembly is still visible so runtime
 * callers can increment their policy generation and clear dependent caches before exposing a new
 * matcher.
 */
class ReloadableDomainPolicy(
    initialAssembly: DomainPolicyAssembly = DomainPolicyAssembler.assemble()
) : DomainMatcher {
    private val currentAssembly = AtomicReference(initialAssembly)

    override fun shouldBlock(domain: String): Boolean =
        currentAssembly.get().matcher.shouldBlock(domain)

    fun snapshot(): DomainPolicyAssembly = currentAssembly.get()

    /**
     * Installs [assembly] after [beforePublish] completes successfully.
     *
     * When [beforePublish] throws, the existing policy remains installed and the exception is
     * propagated to the caller.
     */
    fun install(
        assembly: DomainPolicyAssembly,
        beforePublish: () -> Unit = {}
    ): CompiledBlocklistStatus = synchronized(this) {
        beforePublish()
        currentAssembly.set(assembly)
        assembly.compiledBlocklistStatus
    }
}
