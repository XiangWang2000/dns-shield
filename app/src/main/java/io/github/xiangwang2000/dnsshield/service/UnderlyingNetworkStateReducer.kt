package io.github.xiangwang2000.dnsshield.service

internal enum class UnderlyingNetworkConnectivity {
    OFFLINE,
    CONNECTING,
    CAPTIVE_PORTAL,
    ONLINE,
    UNKNOWN
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
    val selectedTransportMask: Int = 0,
    val candidateConnectivity: UnderlyingNetworkConnectivity = connectivity
)

internal data class UnderlyingNetworkTransition(
    val previous: UnderlyingNetworkSnapshot,
    val current: UnderlyingNetworkSnapshot,
    val effectiveRouteChanged: Boolean =
        previous.connectivity != current.connectivity ||
            previous.selectedNetworkId != current.selectedNetworkId ||
            previous.selectedTransportMask != current.selectedTransportMask,
    val shouldFenceDnsState: Boolean = effectiveRouteChanged
)

internal inline fun UnderlyingNetworkTransition.runIfDnsStateFenceRequired(onChange: () -> Unit): Boolean {
    if (!shouldFenceDnsState) return false
    onChange()
    return true
}

internal fun shouldReplaceNetworkStatusDebounce(
    networkChangePending: Boolean,
    incomingRouteChange: Boolean
): Boolean = !networkChangePending || incomingRouteChange

internal fun isCurrentUnderlyingNetworkCallback(
    token: Long,
    currentToken: Long,
    registeredToken: Long?,
    isVpnRunning: Boolean
): Boolean = token == currentToken && registeredToken == token && isVpnRunning

/** Tracks internet-capable non-VPN networks without treating the app's VPN as its own underlay. */
internal class UnderlyingNetworkStateReducer {
    private data class NetworkState(
        val hasInternet: Boolean,
        val isValidated: Boolean,
        val hasCaptivePortal: Boolean,
        val transportMask: Int
    )

    private data class EffectiveRoute(
        val selectionObserved: Boolean,
        val selectedByTransportMask: Boolean,
        val selectedNetworkId: Long?,
        val selectedTransportMask: Int,
        val selectedNetwork: NetworkState?,
        val known: Boolean,
        val connectivity: UnderlyingNetworkConnectivity
    )

    private val networks = HashMap<Long, NetworkState>()
    private var selectedNetworkId: Long? = null
    private var selectedTransportMask = 0
    private var selectedByTransportMask = false
    private var selectionObserved = false

    @Volatile
    private var snapshot = UnderlyingNetworkSnapshot(
        connectivity = UnderlyingNetworkConnectivity.UNKNOWN,
        networkCount = 0,
        candidateConnectivity = UnderlyingNetworkConnectivity.OFFLINE
    )

    @Synchronized
    fun update(facts: UnderlyingNetworkFacts): UnderlyingNetworkTransition? {
        if (facts.isVpn) return null

        val previousSnapshot = snapshot
        val previousRoute = effectiveRoute()

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
        return publishSnapshot(previousSnapshot, previousRoute, conservativeCandidateChange = true)
    }

    @Synchronized
    fun selectDefaultNetwork(networkId: Long?): UnderlyingNetworkTransition? {
        val transportMask = networkId?.let { networks[it]?.transportMask } ?: 0
        if (
            selectionObserved && !selectedByTransportMask &&
            selectedNetworkId == networkId && selectedTransportMask == transportMask
        ) {
            return null
        }
        val previousSnapshot = snapshot
        val previousRoute = effectiveRoute()
        selectedNetworkId = networkId
        selectedTransportMask = transportMask
        selectedByTransportMask = false
        selectionObserved = true
        return publishSnapshot(previousSnapshot, previousRoute)
    }

    @Synchronized
    fun selectDefaultNetworkByTransportMask(transportMask: Int): UnderlyingNetworkTransition? {
        val networkId = uniqueNetworkForTransportMask(transportMask)
        if (
            selectionObserved && selectedByTransportMask &&
            selectedTransportMask == transportMask && selectedNetworkId == networkId
        ) {
            return null
        }
        val previousSnapshot = snapshot
        val previousRoute = effectiveRoute()
        selectedNetworkId = networkId
        selectedTransportMask = transportMask
        selectedByTransportMask = true
        selectionObserved = true
        return publishSnapshot(previousSnapshot, previousRoute)
    }

    @Synchronized
    fun clearSelectedDefaultNetwork(networkId: Long): UnderlyingNetworkTransition? {
        if (selectedNetworkId != networkId) return null
        val previousSnapshot = snapshot
        val previousRoute = effectiveRoute()
        selectedNetworkId = null
        selectedTransportMask = 0
        selectedByTransportMask = false
        selectionObserved = true
        return publishSnapshot(previousSnapshot, previousRoute)
    }

    fun snapshot(): UnderlyingNetworkSnapshot = snapshot

    @Synchronized
    fun clear() {
        networks.clear()
        selectedNetworkId = null
        selectedTransportMask = 0
        selectedByTransportMask = false
        selectionObserved = false
        snapshot = UnderlyingNetworkSnapshot(
            connectivity = UnderlyingNetworkConnectivity.UNKNOWN,
            networkCount = 0,
            candidateConnectivity = UnderlyingNetworkConnectivity.OFFLINE
        )
    }

    private fun uniqueNetworkForTransportMask(transportMask: Int): Long? {
        if (transportMask == 0) return null
        val matches = networks.filterValues { it.transportMask == transportMask }.keys
        return matches.singleOrNull()
    }

    private fun effectiveRoute(): EffectiveRoute {
        val selectedNetwork = selectedNetworkId?.let(networks::get)
        val known = when {
            selectedNetwork != null -> true
            !selectionObserved -> false
            selectedByTransportMask -> false
            selectedNetworkId != null -> false
            networks.isEmpty() -> true
            else -> false
        }
        val connectivity = when {
            !known -> UnderlyingNetworkConnectivity.UNKNOWN
            selectedNetwork == null -> UnderlyingNetworkConnectivity.OFFLINE
            selectedNetwork.hasCaptivePortal -> UnderlyingNetworkConnectivity.CAPTIVE_PORTAL
            selectedNetwork.hasInternet && selectedNetwork.isValidated -> UnderlyingNetworkConnectivity.ONLINE
            selectedNetwork.hasInternet -> UnderlyingNetworkConnectivity.CONNECTING
            else -> UnderlyingNetworkConnectivity.OFFLINE
        }
        return EffectiveRoute(
            selectionObserved = selectionObserved,
            selectedByTransportMask = selectedByTransportMask,
            selectedNetworkId = selectedNetworkId,
            selectedTransportMask = selectedTransportMask,
            selectedNetwork = selectedNetwork,
            known = known,
            connectivity = connectivity
        )
    }

    private fun candidateConnectivity(): UnderlyingNetworkConnectivity = when {
        networks.values.any { it.hasInternet && it.isValidated } ->
            UnderlyingNetworkConnectivity.ONLINE
        networks.values.any { it.hasCaptivePortal } ->
            UnderlyingNetworkConnectivity.CAPTIVE_PORTAL
        networks.isNotEmpty() -> UnderlyingNetworkConnectivity.CONNECTING
        else -> UnderlyingNetworkConnectivity.OFFLINE
    }

    private fun publishSnapshot(
        previousSnapshot: UnderlyingNetworkSnapshot,
        previousRoute: EffectiveRoute,
        conservativeCandidateChange: Boolean = false
    ): UnderlyingNetworkTransition? {
        val currentRoute = effectiveRoute()
        val nextSnapshot = UnderlyingNetworkSnapshot(
            connectivity = currentRoute.connectivity,
            networkCount = networks.size,
            selectedNetworkId = selectedNetworkId,
            selectedTransportMask = selectedTransportMask,
            candidateConnectivity = candidateConnectivity()
        )
        val effectiveRouteChanged = previousRoute != currentRoute
        // With an unknown selection, candidate changes may have affected the real route.
        val shouldFenceDnsState = effectiveRouteChanged ||
            (conservativeCandidateChange && (!previousRoute.known || !currentRoute.known))
        if (nextSnapshot == previousSnapshot && !shouldFenceDnsState) return null
        snapshot = nextSnapshot
        return UnderlyingNetworkTransition(
            previousSnapshot,
            nextSnapshot,
            effectiveRouteChanged,
            shouldFenceDnsState
        )
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
