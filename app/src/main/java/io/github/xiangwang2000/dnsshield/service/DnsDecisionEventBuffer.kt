package io.github.xiangwang2000.dnsshield.service

import io.github.xiangwang2000.dnsshield.blocking.DomainNameNormalizer
import java.util.Collections
import java.util.LinkedHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Retains facts in the background, copying snapshots only for foreground publication. */
internal class DnsDecisionEventBuffer(
    private val scope: CoroutineScope,
    private val publish: (List<DnsDecisionEvent>) -> Unit,
    private val capacity: Int = 100,
    private val currentTimeMillis: () -> Long = System::currentTimeMillis,
    private val awaitBatch: suspend () -> Unit = { delay(300L) }
) {
    private val lock = Any()
    private val events = LinkedHashMap<String, DnsDecisionEvent>(capacity, 0.75f, true)
    private var nextId = 0L
    private var foreground = false
    private var dirty = false
    private var batchJob: Job? = null
    private var batchToken = 0L

    init { require(capacity > 0) }

    fun record(
        domain: String,
        reason: DnsDecisionReason,
        decision: DnsDecision = DnsDecision.BLOCK
    ) = synchronized(lock) {
        val normalizedDomain = DomainNameNormalizer.normalize(domain) ?: return@synchronized
        val occurredAtMillis = currentTimeMillis()
        val previous = events[normalizedDomain]
        val event = previous?.copy(
            decision = decision,
            reason = reason,
            occurredAtMillis = occurredAtMillis,
            recordCount = previous.recordCount + 1
        ) ?: DnsDecisionEvent(
            ++nextId,
            normalizedDomain,
            decision,
            reason,
            occurredAtMillis
        )
        events[normalizedDomain] = event
        if (events.size > capacity) {
            val oldest = events.entries.iterator()
            oldest.next()
            oldest.remove()
        }
        dirty = true
        if (foreground && batchJob == null) scheduleBatch()
    }

    fun setForeground(value: Boolean) = synchronized(lock) {
        if (foreground == value) return@synchronized
        foreground = value
        cancelBatch()
        if (foreground) {
            dirty = false
            publishSnapshot()
        }
    }

    fun clear() = synchronized(lock) {
        cancelBatch()
        events.clear()
        dirty = false
        publish(emptyList())
    }

    private fun cancelBatch() {
        batchToken++
        batchJob?.cancel()
        batchJob = null
    }

    private fun scheduleBatch() {
        val token = ++batchToken
        batchJob = scope.launch(start = CoroutineStart.LAZY) {
            awaitBatch()
            synchronized(lock) {
                if (token != batchToken || !foreground) return@synchronized
                batchJob = null
                if (dirty) {
                    dirty = false
                    publishSnapshot()
                }
            }
        }
        batchJob?.start()
    }

    private fun publishSnapshot() {
        // The same lock serializes clear(), visibility changes and publication.
        val snapshot = ArrayList(events.values)
        Collections.reverse(snapshot)
        publish(Collections.unmodifiableList(snapshot))
    }
}
