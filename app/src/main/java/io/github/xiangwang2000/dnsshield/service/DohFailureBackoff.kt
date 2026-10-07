package io.github.xiangwang2000.dnsshield.service

/**
 * Temporarily bypasses a failing DoH endpoint while allowing one recovery probe after cooldown.
 */
internal class DohFailureBackoff(
    private val failureThreshold: Int = DEFAULT_FAILURE_THRESHOLD,
    cooldownMillis: Long = DEFAULT_COOLDOWN_MILLIS,
    private val nanoTime: () -> Long = System::nanoTime
) {
    data class Generation(val resolverGeneration: Int, val networkGeneration: Long)

    private data class EndpointIdentity(
        val url: String,
        val hostname: String,
        val bootstrapAddresses: List<String>,
        val isCustom: Boolean
    )

    private class State(
        var consecutiveFailures: Int = 0,
        var retryAfterNanos: Long = 0L,
        var probeInFlight: Boolean = false
    )

    private val cooldownNanos = cooldownMillis * NANOS_PER_MILLISECOND
    private val lock = Any()
    private val states = HashMap<EndpointIdentity, State>()
    private var activeGeneration = Generation(resolverGeneration = 0, networkGeneration = 0L)

    init {
        require(failureThreshold > 0)
        require(cooldownMillis > 0)
    }

    fun tryAcquire(endpoint: DnsDohEndpoint, generation: Generation): Boolean = synchronized(lock) {
        if (generation != activeGeneration) return@synchronized false
        tryAcquireLocked(endpoint.identity())
    }

    private fun tryAcquireLocked(endpoint: EndpointIdentity): Boolean {
        val state = states[endpoint] ?: return true
        if (state.retryAfterNanos == 0L) return true

        val now = nanoTime()
        if (now < state.retryAfterNanos || state.probeInFlight) return false

        state.probeInFlight = true
        return true
    }

    fun recordSuccess(endpoint: DnsDohEndpoint, generation: Generation) {
        synchronized(lock) {
            if (generation == activeGeneration) states.remove(endpoint.identity())
        }
    }

    fun recordFailure(endpoint: DnsDohEndpoint, generation: Generation) {
        synchronized(lock) {
            if (generation == activeGeneration) recordFailureLocked(endpoint.identity())
        }
    }

    private fun recordFailureLocked(endpoint: EndpointIdentity) {
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

    fun cancelAttempt(endpoint: DnsDohEndpoint, generation: Generation) {
        synchronized(lock) {
            if (generation == activeGeneration) states[endpoint.identity()]?.probeInFlight = false
        }
    }

    fun resetForGeneration(generation: Generation) {
        synchronized(lock) {
            if (generation != activeGeneration) {
                activeGeneration = generation
                states.clear()
            }
        }
    }

    private fun DnsDohEndpoint.identity() = EndpointIdentity(
        url = url,
        hostname = hostname,
        bootstrapAddresses = bootstrapAddresses.toList(),
        isCustom = isCustom
    )

    private companion object {
        const val DEFAULT_FAILURE_THRESHOLD = 3
        const val DEFAULT_COOLDOWN_MILLIS = 15_000L
        const val NANOS_PER_MILLISECOND = 1_000_000L
    }
}
