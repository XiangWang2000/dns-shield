package io.github.xiangwang2000.dnsshield.service

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeoutOrNull

/** A retained notification prevents lost wakeups between reading state and suspending. */
internal class DnsNetworkReadiness {
    enum class State { READY, WAITING, STALE }

    private val changes = MutableStateFlow(0L)

    // The caller updates its authoritative state and signals while holding the same state lock.
    fun signalChange() {
        changes.update { it + 1L }
    }

    suspend fun awaitReady(deadline: DnsRequestDeadline, readState: () -> State): Boolean {
        val remainingMillis = deadline.remainingMillis()
        if (remainingMillis <= 0L) return false
        return withTimeoutOrNull(remainingMillis) {
            changes.first { readState() != State.WAITING }
            readState() == State.READY && deadline.remainingMillis() > 0L
        } ?: false
    }
}
