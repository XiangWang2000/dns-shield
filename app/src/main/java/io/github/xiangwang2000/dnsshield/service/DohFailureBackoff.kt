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
    private var activeGeneration = 0L

    init {
        require(failureThreshold > 0)
        require(cooldownMillis > 0)
    }

    fun tryAcquire(endpoint: String): Boolean = synchronized(lock) {
        tryAcquireLocked(endpoint)
    }

    fun tryAcquire(endpoint: String, generation: Long): Boolean = synchronized(lock) {
        if (generation != activeGeneration) return@synchronized false
        tryAcquireLocked(endpoint)
    }

    private fun tryAcquireLocked(endpoint: String): Boolean {
        val state = states[endpoint] ?: return true
        if (state.retryAfterNanos == 0L) return true

        val now = nanoTime()
        if (now < state.retryAfterNanos || state.probeInFlight) return false

        state.probeInFlight = true
        return true
    }

    fun recordSuccess(endpoint: String) {
        synchronized(lock) {
            states.remove(endpoint)
        }
    }

    fun recordSuccess(endpoint: String, generation: Long) {
        synchronized(lock) {
            if (generation == activeGeneration) states.remove(endpoint)
        }
    }

    fun recordFailure(endpoint: String) {
        synchronized(lock) {
            recordFailureLocked(endpoint)
        }
    }

    fun recordFailure(endpoint: String, generation: Long) {
        synchronized(lock) {
            if (generation == activeGeneration) recordFailureLocked(endpoint)
        }
    }

    private fun recordFailureLocked(endpoint: String) {
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

    fun cancelAttempt(endpoint: String) {
        synchronized(lock) {
            states[endpoint]?.probeInFlight = false
        }
    }

    fun cancelAttempt(endpoint: String, generation: Long) {
        synchronized(lock) {
            if (generation == activeGeneration) states[endpoint]?.probeInFlight = false
        }
    }

    fun resetForGeneration(generation: Long) {
        synchronized(lock) {
            if (generation != activeGeneration) {
                activeGeneration = generation
                states.clear()
            }
        }
    }

    private companion object {
        const val DEFAULT_FAILURE_THRESHOLD = 3
        const val DEFAULT_COOLDOWN_MILLIS = 15_000L
        const val NANOS_PER_MILLISECOND = 1_000_000L
    }
}
