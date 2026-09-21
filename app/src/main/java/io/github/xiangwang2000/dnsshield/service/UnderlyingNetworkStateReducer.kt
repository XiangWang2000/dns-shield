package io.github.xiangwang2000.dnsshield.service

internal enum class UnderlyingNetworkConnectivity {
    OFFLINE,
    CONNECTING,
    CAPTIVE_PORTAL,
    ONLINE
}

internal data class UnderlyingNetworkFacts(
    val networkId: Long,
    val isVpn: Boolean,
    val hasInternet: Boolean,
    val isValidated: Boolean,
    val hasCaptivePortal: Boolean,
    val transportMask: Int = 0,
    val lost: Boolean = false
)

internal data class UnderlyingNetworkSnapshot(
    val connectivity: UnderlyingNetworkConnectivity,
    val networkCount: Int,
    val selectedNetworkId: Long? = null,
    val selectedTransportMask: Int = 0
)

internal data class UnderlyingNetworkTransition(
    val previous: UnderlyingNetworkSnapshot,
    val current: UnderlyingNetworkSnapshot
)

/** Tracks internet-capable non-VPN networks without treating the app's VPN as its own underlay. */
internal class UnderlyingNetworkStateReducer {
    private data class NetworkState(
        val hasInternet: Boolean,
        val isValidated: Boolean,
        val hasCaptivePortal: Boolean,
        val transportMask: Int
    )

    private val networks = HashMap<Long, NetworkState>()
    private var selectedNetworkId: Long? = null
    private var selectedTransportMask = 0
    private var selectedByTransportMask = false

    @Volatile
    private var snapshot = UnderlyingNetworkSnapshot(
        connectivity = UnderlyingNetworkConnectivity.OFFLINE,
        networkCount = 0
    )

    @Synchronized
    fun update(facts: UnderlyingNetworkFacts): UnderlyingNetworkTransition? {
        if (facts.isVpn) return null

        val previousNetwork = networks[facts.networkId]
        val nextNetwork = if (facts.lost || (!facts.hasInternet && !facts.hasCaptivePortal)) {
            null
        } else {
            NetworkState(
                hasInternet = facts.hasInternet,
                isValidated = facts.isValidated,
                hasCaptivePortal = facts.hasCaptivePortal,
                transportMask = facts.transportMask
            )
        }
        if (previousNetwork == nextNetwork) return null

        if (nextNetwork == null) networks.remove(facts.networkId)
        else networks[facts.networkId] = nextNetwork

        if (selectedByTransportMask) {
            selectedNetworkId = uniqueNetworkForTransportMask(selectedTransportMask)
        } else if (selectedNetworkId != null) {
            selectedTransportMask = networks[selectedNetworkId]?.transportMask ?: 0
        }
        return publishSnapshot()
    }

    @Synchronized
    fun selectDefaultNetwork(networkId: Long?): UnderlyingNetworkTransition? {
        val transportMask = networkId?.let { networks[it]?.transportMask } ?: 0
        if (!selectedByTransportMask && selectedNetworkId == networkId && selectedTransportMask == transportMask) {
            return null
        }
        selectedNetworkId = networkId
        selectedTransportMask = transportMask
        selectedByTransportMask = false
        return publishSnapshot()
    }

    @Synchronized
    fun selectDefaultNetworkByTransportMask(transportMask: Int): UnderlyingNetworkTransition? {
        val networkId = uniqueNetworkForTransportMask(transportMask)
        if (selectedByTransportMask && selectedTransportMask == transportMask && selectedNetworkId == networkId) {
            return null
        }
        selectedNetworkId = networkId
        selectedTransportMask = transportMask
        selectedByTransportMask = true
        return publishSnapshot()
    }

    @Synchronized
    fun clearSelectedDefaultNetwork(networkId: Long): UnderlyingNetworkTransition? {
        if (selectedNetworkId != networkId) return null
        selectedNetworkId = null
        selectedTransportMask = 0
        selectedByTransportMask = false
        return publishSnapshot()
    }

    fun snapshot(): UnderlyingNetworkSnapshot = snapshot

    @Synchronized
    fun clear() {
        networks.clear()
        selectedNetworkId = null
        selectedTransportMask = 0
        selectedByTransportMask = false
        snapshot = UnderlyingNetworkSnapshot(
            connectivity = UnderlyingNetworkConnectivity.OFFLINE,
            networkCount = 0
        )
    }

    private fun uniqueNetworkForTransportMask(transportMask: Int): Long? {
        if (transportMask == 0) return null
        val matches = networks.filterValues { it.transportMask == transportMask }.keys
        return matches.singleOrNull()
    }

    private fun publishSnapshot(): UnderlyingNetworkTransition? {
        val previousSnapshot = snapshot
        val connectivity = when {
            networks.values.any { it.hasInternet && it.isValidated } ->
                UnderlyingNetworkConnectivity.ONLINE
            networks.values.any { it.hasCaptivePortal } ->
                UnderlyingNetworkConnectivity.CAPTIVE_PORTAL
            networks.isNotEmpty() -> UnderlyingNetworkConnectivity.CONNECTING
            else -> UnderlyingNetworkConnectivity.OFFLINE
        }
        val nextSnapshot = UnderlyingNetworkSnapshot(
            connectivity = connectivity,
            networkCount = networks.size,
            selectedNetworkId = selectedNetworkId,
            selectedTransportMask = selectedTransportMask
        )
        if (nextSnapshot == previousSnapshot) return null
        snapshot = nextSnapshot
        return UnderlyingNetworkTransition(previousSnapshot, nextSnapshot)
    }
}

internal data class NetworkRecoveryMeasurement(
    val durationMillis: Long?,
    val failedQueryCount: Int
)

/** Measures one outage through its first stable return to an online state. */
internal class UnderlyingNetworkRecoveryTracker {
    private var startedAtNanos: Long? = null
    private var completedAtNanos: Long? = null
    private var failedQueryCount = 0

    @Synchronized
    fun observe(transition: UnderlyingNetworkTransition, nowNanos: Long) {
        val wasOnline = transition.previous.connectivity == UnderlyingNetworkConnectivity.ONLINE
        val isOnline = transition.current.connectivity == UnderlyingNetworkConnectivity.ONLINE
        when {
            wasOnline && !isOnline -> {
                if (startedAtNanos == null) {
                    startedAtNanos = nowNanos
                    failedQueryCount = 0
                }
                completedAtNanos = null
            }
            !wasOnline && isOnline && startedAtNanos != null -> completedAtNanos = nowNanos
            !isOnline -> completedAtNanos = null
        }
    }

    @Synchronized
    fun recordFailure() {
        if (startedAtNanos != null && completedAtNanos == null) failedQueryCount++
    }

    @Synchronized
    fun takeCompletedMeasurement(): NetworkRecoveryMeasurement? {
        val completed = completedAtNanos ?: return null
        val started = startedAtNanos
        val measurement = NetworkRecoveryMeasurement(
            durationMillis = started?.let { (completed - it).coerceAtLeast(0L) / 1_000_000L },
            failedQueryCount = failedQueryCount
        )
        startedAtNanos = null
        completedAtNanos = null
        failedQueryCount = 0
        return measurement
    }

    @Synchronized
    fun clear() {
        startedAtNanos = null
        completedAtNanos = null
        failedQueryCount = 0
    }
}
