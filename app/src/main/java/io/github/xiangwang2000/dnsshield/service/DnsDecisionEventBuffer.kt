package io.github.xiangwang2000.dnsshield.service

import java.util.ArrayDeque
import java.util.Collections
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
    private val events = ArrayDeque<DnsDecisionEvent>()
    private var nextId = 0L
    private var foreground = false
    private var dirty = false
    private var batchJob: Job? = null
    private var batchToken = 0L

    init { require(capacity > 0) }

    fun record(domain: String, reason: DnsDecisionReason) = synchronized(lock) {
        if (events.size == capacity) events.removeLast()
        events.addFirst(DnsDecisionEvent(++nextId, domain, DnsDecision.BLOCK, reason, currentTimeMillis()))
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
        publish(Collections.unmodifiableList(ArrayList(events)))
    }
}
