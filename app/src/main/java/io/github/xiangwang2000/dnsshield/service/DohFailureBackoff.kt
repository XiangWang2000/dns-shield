package io.github.xiangwang2000.dnsshield.service

/**
 * Temporarily bypasses a failing DoH endpoint while allowing one recovery probe after cooldown.
 */
internal class DohFailureBackoff(
    private val failureThreshold: Int = DEFAULT_FAILURE_THRESHOLD,
    cooldownMillis: Long = DEFAULT_COOLDOWN_MILLIS,
    private val nanoTime: () -> Long = System::nanoTime
) {
    private class State(
        var consecutiveFailures: Int = 0,
        var retryAfterNanos: Long = 0L,
        var probeInFlight: Boolean = false
    )

    private val cooldownNanos = cooldownMillis * NANOS_PER_MILLISECOND
    private val lock = Any()
    private val states = HashMap<String, State>()

    init {
        require(failureThreshold > 0)
        require(cooldownMillis > 0)
    }

    fun tryAcquire(endpoint: String): Boolean = synchronized(lock) {
        val state = states[endpoint] ?: return true
        if (state.retryAfterNanos == 0L) return true

        val now = nanoTime()
        if (now < state.retryAfterNanos || state.probeInFlight) return false

        state.probeInFlight = true
        true
    }

    fun recordSuccess(endpoint: String) {
        synchronized(lock) {
            states.remove(endpoint)
        }
    }

    fun recordFailure(endpoint: String) {
        synchronized(lock) {
            val now = nanoTime()
            val state = states.getOrPut(endpoint, ::State)

            if (state.retryAfterNanos > now && !state.probeInFlight) {
                return
            }

            state.probeInFlight = false
            state.consecutiveFailures++
            if (state.consecutiveFailures >= failureThreshold) {
                state.retryAfterNanos = now + cooldownNanos
            }
        }
    }

    fun cancelAttempt(endpoint: String) {
        synchronized(lock) {
            states[endpoint]?.probeInFlight = false
        }
    }

    private companion object {
        const val DEFAULT_FAILURE_THRESHOLD = 3
        const val DEFAULT_COOLDOWN_MILLIS = 15_000L
        const val NANOS_PER_MILLISECOND = 1_000_000L
    }
}
