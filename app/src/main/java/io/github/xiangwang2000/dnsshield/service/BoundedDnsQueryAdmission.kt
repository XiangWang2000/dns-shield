package io.github.xiangwang2000.dnsshield.service

import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CompletableDeferred

internal sealed interface DnsQueryAdmission<out K> {
    data class Leader<K>(val lease: BoundedDnsQueryAdmission.Lease<K>) : DnsQueryAdmission<K>
    data class Waiter<K>(val lease: BoundedDnsQueryAdmission.Lease<K>) : DnsQueryAdmission<K>
    data object Rejected : DnsQueryAdmission<Nothing>
}

/** A non-blocking registry whose entries remain counted until every admitted client exits. */
internal class BoundedDnsQueryAdmission<K>(
    private val maxUniqueKeys: Int,
    private val maxWaitersPerKey: Int
) {
    internal class Entry<K>(val key: K) {
        val result = CompletableDeferred<ByteArray?>()
        var activeRequests = 1
        var activeWaiters = 0
        var leaderCompleted = false
    }

    internal class Lease<K> internal constructor(
        internal val entry: Entry<K>,
        val isLeader: Boolean
    ) {
        val result: CompletableDeferred<ByteArray?>
            get() = entry.result

        private val released = AtomicBoolean(false)

        internal fun markReleased(): Boolean = released.compareAndSet(false, true)
    }

    internal data class Snapshot(
        val uniqueKeys: Int,
        val activeRequests: Int,
        val activeWaiters: Int
    )

    private val lock = Any()
    private val entries = HashMap<K, Entry<K>>()

    init {
        require(maxUniqueKeys > 0)
        require(maxWaitersPerKey >= 0)
    }

    /** Returns immediately; overload is explicit and never waits for an upstream permit. */
    fun tryAdmit(key: K): DnsQueryAdmission<K> = synchronized(lock) {
        val existing = entries[key]
        if (existing != null) {
            if (existing.activeWaiters >= maxWaitersPerKey) return@synchronized DnsQueryAdmission.Rejected
            existing.activeWaiters++
            existing.activeRequests++
            return@synchronized DnsQueryAdmission.Waiter(Lease(existing, isLeader = false))
        }

        if (entries.size >= maxUniqueKeys) return@synchronized DnsQueryAdmission.Rejected
        val entry = Entry(key)
        entries[key] = entry
        DnsQueryAdmission.Leader(Lease(entry, isLeader = true))
    }

    fun completeLeader(lease: Lease<K>, result: ByteArray?) {
        require(lease.isLeader)
        val shouldComplete = synchronized(lock) {
            if (lease.entry.leaderCompleted) false else {
                lease.entry.leaderCompleted = true
                true
            }
        }
        if (shouldComplete) lease.result.complete(result)
    }

    /** Idempotent so both coroutine finally blocks and completion handlers may release safely. */
    fun release(lease: Lease<K>) {
        if (!lease.markReleased()) return

        var completeFailedLeader = false
        synchronized(lock) {
            val entry = lease.entry
            if (lease.isLeader && !entry.leaderCompleted) {
                entry.leaderCompleted = true
                completeFailedLeader = true
            }
            if (!lease.isLeader) entry.activeWaiters--
            entry.activeRequests--
            check(entry.activeRequests >= 0 && entry.activeWaiters >= 0)
            if (entry.activeRequests == 0) entries.remove(entry.key, entry)
        }

        if (completeFailedLeader) lease.result.complete(null)
    }

    fun snapshot(): Snapshot = synchronized(lock) {
        Snapshot(
            uniqueKeys = entries.size,
            activeRequests = entries.values.sumOf { it.activeRequests },
            activeWaiters = entries.values.sumOf { it.activeWaiters }
        )
    }
}
