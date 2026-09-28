package io.github.xiangwang2000.dnsshield.service

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.ConcurrentHashMap

internal class DnsPlaintextFallbackFence {
    private class ResolverPolicy(var allowPlaintextFallback: Boolean = true) {
        val activeTcpSockets = HashSet<Socket>()
    }

    private val policies = ConcurrentHashMap<Int, ResolverPolicy>()

    fun setAllowed(resolverId: Int, allowed: Boolean) {
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        synchronized(policy) {
            policy.allowPlaintextFallback = allowed
            if (!allowed) {
                policy.activeTcpSockets.forEach { socket -> runCatching { socket.close() } }
                policy.activeTcpSockets.clear()
            }
        }
    }

    fun allows(resolverId: Int): Boolean {
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        return synchronized(policy) { policy.allowPlaintextFallback }
    }

    fun registerTcpSocketIfAllowed(
        resolverId: Int,
        snapshotAllowsPlaintext: Boolean,
        currentPolicyAllowsPlaintext: () -> Boolean,
        socket: Socket
    ): Boolean {
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        return synchronized(policy) {
            if (!snapshotAllowsPlaintext || !policy.allowPlaintextFallback ||
                !currentPolicyAllowsPlaintext()
            ) {
                false
            } else {
                policy.activeTcpSockets.add(socket)
            }
        }
    }

    fun unregisterTcpSocket(resolverId: Int, socket: Socket) {
        val policy = policies.computeIfAbsent(resolverId) { ResolverPolicy() }
        synchronized(policy) { policy.activeTcpSockets.remove(socket) }
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
