package io.github.xiangwang2000.dnsshield.service

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap

internal class DnsPlaintextFallbackFence {
    private class ResolverPolicy(var allowPlaintextFallback: Boolean = true)

    private val policies = ConcurrentHashMap<Int, ResolverPolicy>()

    fun setAllowed(resolverId: Int, allowed: Boolean) {
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        synchronized(policy) {
            policy.allowPlaintextFallback = allowed
        }
    }

    fun allows(resolverId: Int): Boolean {
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        return synchronized(policy) { policy.allowPlaintextFallback }
    }

    fun sendIfAllowed(
        resolverId: Int,
        snapshotAllowsPlaintext: Boolean,
        currentPolicyAllowsPlaintext: () -> Boolean,
        send: () -> Unit
    ): Boolean {
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        return synchronized(policy) {
            if (!snapshotAllowsPlaintext || !policy.allowPlaintextFallback ||
                !currentPolicyAllowsPlaintext()
            ) {
                false
            } else {
                send()
                true
            }
        }
    }
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
