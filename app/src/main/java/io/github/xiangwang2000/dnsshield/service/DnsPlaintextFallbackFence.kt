package io.github.xiangwang2000.dnsshield.service

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference

internal class DnsPlaintextFallbackFence {
    private data class RequestedPolicy(
        val revision: Long,
        val allowed: Boolean,
        val persisted: Boolean
    )

    private data class PolicyState(
        val requested: RequestedPolicy? = null,
        val appliedRevision: Long = Long.MIN_VALUE,
        val allowPlaintextFallback: Boolean = true,
        val inFlightWrites: Int = 0
    )

    private class ResolverPolicy {
        val state = AtomicReference(PolicyState())
        val activeTcpSockets = ConcurrentHashMap<Socket, Long>()
    }

    private data class SendPermit(
        val policy: ResolverPolicy,
        val revision: Long
    )

    private val policies = ConcurrentHashMap<Int, ResolverPolicy>()

    /**
     * Publishes the latest UI request with a lock-free CAS.
     * STRICT takes effect before persistence; ALLOW remains pending until saved and applied.
     */
    fun requestPolicy(resolverId: Int, revision: Long, allowed: Boolean): Boolean {
        require(revision > 0L) { "A policy request must have a positive revision" }
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        while (true) {
            val current = policy.state.get()
            val requested = current.requested
            val latestRevision = maxOf(requested?.revision ?: Long.MIN_VALUE, current.appliedRevision)
            if (revision < latestRevision) return false
            if (requested?.revision == revision) {
                if (requested.allowed != allowed) return false
                if (allowed || !current.allowPlaintextFallback) return true
                if (policy.state.compareAndSet(
                        current,
                        current.copy(allowPlaintextFallback = false)
                    )
                ) {
                    return true
                }
            } else {
                val next = current.copy(
                    requested = RequestedPolicy(revision, allowed, persisted = false),
                    allowPlaintextFallback = if (allowed) {
                        current.allowPlaintextFallback
                    } else {
                        false
                    }
                )
                if (policy.state.compareAndSet(current, next)) return true
            }
        }
    }

    /** Called only after the matching Room mutation succeeded. */
    fun markPersisted(resolverId: Int, revision: Long, allowed: Boolean): Boolean {
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        while (true) {
            val current = policy.state.get()
            val requested = current.requested ?: return false
            if (requested.revision != revision || requested.allowed != allowed) return false
            if (requested.persisted) return true
            if (policy.state.compareAndSet(
                    current,
                    current.copy(requested = requested.copy(persisted = true))
                )
            ) {
                return true
            }
        }
    }

    /**
     * Reconciles a service command or the latest active DB row.
     * A newer unsaved request, especially a failed STRICT write, cannot be overwritten by an old row.
     */
    fun applyStoredPolicy(resolverId: Int, revision: Long, allowed: Boolean): Boolean {
        require(revision >= 0L) { "A service policy revision cannot be negative" }
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        while (true) {
            val current = policy.state.get()
            if (revision < current.appliedRevision) return false
            val requested = current.requested
            if (requested != null && (
                    !requested.persisted ||
                        requested.allowed != allowed ||
                        revision < requested.revision
                    )
            ) {
                return false
            }
            val next = current.copy(
                appliedRevision = revision,
                allowPlaintextFallback = allowed
            )
            if (next == current || policy.state.compareAndSet(current, next)) return true
        }
    }

    fun allows(resolverId: Int): Boolean =
        policies.computeIfAbsent(resolverId) { ResolverPolicy() }
            .state.get().allowPlaintextFallback

    /**
     * Runs cleanup outside the submission lock. The socket registry is concurrent so a strict
     * publication never waits for an in-flight write's policy state.
     */
    fun closeSocketsIfStillStrict(resolverId: Int, strictRevision: Long) {
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        val state = policy.state.get()
        if (!isDeniedAtOrAfter(state, strictRevision)) return

        val snapshot = policy.activeTcpSockets.entries
            .filter { it.value <= strictRevision }
        for ((socket, socketRevision) in snapshot) {
            if (!isDeniedAtOrAfter(policy.state.get(), strictRevision)) return
            if (policy.activeTcpSockets.remove(socket, socketRevision)) {
                runCatching { socket.close() }
            }
        }
    }

    fun registerTcpSocketIfAllowed(
        resolverId: Int,
        snapshotAllowsPlaintext: Boolean,
        currentPolicyAllowsPlaintext: () -> Boolean,
        socket: Socket
    ): Boolean {
        val permit = acquireSendPermit(
            resolverId,
            snapshotAllowsPlaintext,
            currentPolicyAllowsPlaintext
        ) ?: return false
        try {
            permit.policy.activeTcpSockets[socket] = permit.revision
            if (!permit.policy.state.get().allowPlaintextFallback ||
                !currentPolicyAllowsPlaintext()
            ) {
                permit.policy.activeTcpSockets.remove(socket, permit.revision)
                runCatching { socket.close() }
                return false
            }
            return true
        } catch (failure: Throwable) {
            permit.policy.activeTcpSockets.remove(socket, permit.revision)
            runCatching { socket.close() }
            throw failure
        } finally {
            releaseSendPermit(permit)
        }
    }

    fun unregisterTcpSocket(resolverId: Int, socket: Socket) {
        policies.computeIfAbsent(resolverId) { ResolverPolicy() }
            .activeTcpSockets.remove(socket)
    }

    fun writeTcpFrameIfAllowed(
        resolverId: Int,
        snapshotAllowsPlaintext: Boolean,
        currentPolicyAllowsPlaintext: () -> Boolean,
        socket: Socket,
        frame: ByteArray
    ): Boolean = sendIfAllowed(
        resolverId,
        snapshotAllowsPlaintext,
        currentPolicyAllowsPlaintext
    ) {
        socket.getOutputStream().apply {
            write(frame)
            flush()
        }
    }

    fun sendIfAllowed(
        resolverId: Int,
        snapshotAllowsPlaintext: Boolean,
        currentPolicyAllowsPlaintext: () -> Boolean,
        send: () -> Unit
    ): Boolean {
        val permit = acquireSendPermit(
            resolverId,
            snapshotAllowsPlaintext,
            currentPolicyAllowsPlaintext
        ) ?: return false
        try {
            send()
            return true
        } finally {
            releaseSendPermit(permit)
        }
    }

    private fun acquireSendPermit(
        resolverId: Int,
        snapshotAllowsPlaintext: Boolean,
        currentPolicyAllowsPlaintext: () -> Boolean
    ): SendPermit? {
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        while (true) {
            val current = policy.state.get()
            if (!snapshotAllowsPlaintext || !current.allowPlaintextFallback) return null
            check(current.inFlightWrites < Int.MAX_VALUE) { "DNS fallback admission count exhausted" }
            if (!policy.state.compareAndSet(
                    current,
                    current.copy(inFlightWrites = current.inFlightWrites + 1)
                )
            ) {
                continue
            }

            val permit = SendPermit(
                policy,
                maxOf(current.appliedRevision, current.requested?.revision ?: Long.MIN_VALUE)
            )
            try {
                if (!currentPolicyAllowsPlaintext() ||
                    !policy.state.get().allowPlaintextFallback
                ) {
                    releaseSendPermit(permit)
                    return null
                }
                return permit
            } catch (failure: Throwable) {
                releaseSendPermit(permit)
                throw failure
            }
        }
    }

    private fun releaseSendPermit(permit: SendPermit) {
        val state = permit.policy.state
        while (true) {
            val current = state.get()
            check(current.inFlightWrites > 0) { "DNS fallback admission count underflow" }
            if (state.compareAndSet(
                    current,
                    current.copy(inFlightWrites = current.inFlightWrites - 1)
                )
            ) {
                return
            }
        }
    }

    private fun isDeniedAtOrAfter(state: PolicyState, revision: Long): Boolean =
        !state.allowPlaintextFallback &&
            maxOf(state.appliedRevision, state.requested?.revision ?: Long.MIN_VALUE) >= revision
}

internal class PolicyFencedDatagramSocket(
    private val resolverId: Int,
    private val snapshotAllowsPlaintext: Boolean,
    private val fence: DnsPlaintextFallbackFence,
    private val currentPolicyAllowsPlaintext: () -> Boolean
) : DatagramSocket() {
    override fun send(packet: DatagramPacket) {
        if (!fence.sendIfAllowed(
                resolverId,
                snapshotAllowsPlaintext,
                currentPolicyAllowsPlaintext
            ) {
                super.send(packet)
            }
        ) {
            throw SocketException("Plaintext DNS fallback is disabled")
        }
    }
}
