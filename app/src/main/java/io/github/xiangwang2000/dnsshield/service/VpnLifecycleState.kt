package io.github.xiangwang2000.dnsshield.service

import java.util.concurrent.atomic.AtomicLong

enum class VpnLifecycleState {
    STOPPED,
    STARTING,
    RUNNING,
    STOPPING,
    FAILED;

    internal val isRunning: Boolean
        get() = this == RUNNING

    internal val canStart: Boolean
        get() = this == STOPPED || this == FAILED

    internal fun toggleAction(): VpnToggleAction = when (this) {
        STOPPED, FAILED -> VpnToggleAction.START
        STARTING, RUNNING -> VpnToggleAction.STOP
        STOPPING -> VpnToggleAction.NONE
    }

    internal fun stateAfterServiceDestroy(): VpnLifecycleState =
        if (this == FAILED) FAILED else STOPPED
}

internal enum class VpnToggleAction {
    START,
    STOP,
    NONE
}

internal class VpnLifecycleRequestTracker {
    private val generation = AtomicLong()

    fun nextRequest(): Long = generation.incrementAndGet()

    fun isCurrent(requestGeneration: Long): Boolean =
        generation.get() == requestGeneration
}
