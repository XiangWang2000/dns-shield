package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UnderlyingNetworkStateReducerTest {
    @Test
    fun ignoresVpnEventsAndReportsNonVpnConnectivity() {
        val reducer = UnderlyingNetworkStateReducer()

        assertNull(reducer.update(facts(networkId = 1, isVpn = true, isValidated = true)))
        assertEquals(
            UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.OFFLINE, 0),
            reducer.snapshot()
        )

        val connecting = reducer.update(facts(networkId = 2))
        assertEquals(UnderlyingNetworkConnectivity.CONNECTING, connecting?.current?.connectivity)

        val online = reducer.update(facts(networkId = 2, isValidated = true))
        assertEquals(UnderlyingNetworkConnectivity.ONLINE, online?.current?.connectivity)
    }

    @Test
    fun reportsCaptivePortalAndReturnsOfflineAfterLastNetworkIsLost() {
        val reducer = UnderlyingNetworkStateReducer()

        val portal = reducer.update(facts(networkId = 7, hasInternet = false, hasCaptivePortal = true))
        assertEquals(UnderlyingNetworkConnectivity.CAPTIVE_PORTAL, portal?.current?.connectivity)

        val offline = reducer.update(facts(networkId = 7, lost = true))
        assertEquals(UnderlyingNetworkConnectivity.OFFLINE, offline?.current?.connectivity)
        assertEquals(0, offline?.current?.networkCount)
    }

    @Test
    fun reportsNetworkIdentityChangesEvenWhenConnectivityRemainsOnline() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(networkId = 1, isValidated = true))
        val secondNetwork = reducer.update(facts(networkId = 2, isValidated = true, transportMask = 2))

        assertEquals(
            UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 2),
            secondNetwork?.current
        )
        val lostFirstNetwork = reducer.update(facts(networkId = 1, lost = true))
        assertEquals(
            UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 1),
            lostFirstNetwork?.current
        )
    }

    @Test
    fun selectedWifiToCellularChangesWhileBothNetworksRemainOnline() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(networkId = 11, isValidated = true, transportMask = 1))
        reducer.update(facts(networkId = 22, isValidated = true, transportMask = 2))

        val wifiSelected = reducer.selectDefaultNetworkByTransportMask(1)
        assertEquals(
            UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 2, 11, 1),
            wifiSelected?.current
        )

        val cellularSelected = reducer.selectDefaultNetworkByTransportMask(2)
        assertEquals(
            UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 2, 22, 2),
            cellularSelected?.current
        )
        assertEquals(2, reducer.snapshot().networkCount)
    }

    @Test
    fun transportSelectionLeavesIdentityUnknownWhenSeveralNetworksMatch() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(networkId = 31, isValidated = true, transportMask = 1))
        reducer.update(facts(networkId = 32, isValidated = true, transportMask = 1))

        reducer.selectDefaultNetworkByTransportMask(1)

        assertEquals(
            UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 2, null, 1),
            reducer.snapshot()
        )
    }

    @Test
    fun emptyTransportSelectionClearsStaleNetworkIdentity() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(networkId = 41, isValidated = true, transportMask = 1))
        reducer.selectDefaultNetworkByTransportMask(1)

        reducer.selectDefaultNetworkByTransportMask(0)

        assertEquals(
            UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 1, null, 0),
            reducer.snapshot()
        )
    }

    @Test
    fun recoveryMeasurementIgnoresOnlineNetworkSelectionChanges() {
        val tracker = UnderlyingNetworkRecoveryTracker()
        tracker.observe(
            transition(
                UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 2, 11, 1),
                UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 2, 22, 2)
            ),
            nowNanos = 1_000_000_000L
        )
        tracker.recordFailure()

        assertNull(tracker.takeCompletedMeasurement())

        tracker.observe(
            transition(
                UnderlyingNetworkConnectivity.ONLINE,
                UnderlyingNetworkConnectivity.CONNECTING
            ),
            nowNanos = 2_000_000_000L
        )
        tracker.recordFailure()
        tracker.observe(
            transition(
                UnderlyingNetworkConnectivity.CONNECTING,
                UnderlyingNetworkConnectivity.ONLINE
            ),
            nowNanos = 2_750_000_000L
        )
        tracker.recordFailure()

        assertEquals(NetworkRecoveryMeasurement(750, 1), tracker.takeCompletedMeasurement())
        assertNull(tracker.takeCompletedMeasurement())
    }

    @Test
    fun initialOfflineConnectingOnlineSequenceIsNotReportedAsRecovery() {
        val tracker = UnderlyingNetworkRecoveryTracker()
        tracker.observe(
            transition(
                UnderlyingNetworkConnectivity.OFFLINE,
                UnderlyingNetworkConnectivity.CONNECTING
            ),
            nowNanos = 1_000_000_000L
        )
        tracker.recordFailure()
        tracker.observe(
            transition(
                UnderlyingNetworkConnectivity.CONNECTING,
                UnderlyingNetworkConnectivity.ONLINE
            ),
            nowNanos = 1_750_000_000L
        )

        assertNull(tracker.takeCompletedMeasurement())
    }

    @Test
    fun flappingBeforeDebouncedRecoveryKeepsOutageStartAndNextOutageStartsFresh() {
        val tracker = UnderlyingNetworkRecoveryTracker()
        tracker.observe(
            transition(
                UnderlyingNetworkConnectivity.ONLINE,
                UnderlyingNetworkConnectivity.CONNECTING
            ),
            nowNanos = 0L
        )
        tracker.recordFailure()
        tracker.observe(
            transition(
                UnderlyingNetworkConnectivity.CONNECTING,
                UnderlyingNetworkConnectivity.ONLINE
            ),
            nowNanos = 100_000_000L
        )
        tracker.observe(
            transition(
                UnderlyingNetworkConnectivity.ONLINE,
                UnderlyingNetworkConnectivity.CONNECTING
            ),
            nowNanos = 200_000_000L
        )
        tracker.recordFailure()
        tracker.observe(
            transition(
                UnderlyingNetworkConnectivity.CONNECTING,
                UnderlyingNetworkConnectivity.ONLINE
            ),
            nowNanos = 900_000_000L
        )

        assertEquals(NetworkRecoveryMeasurement(900, 2), tracker.takeCompletedMeasurement())
        assertNull(tracker.takeCompletedMeasurement())

        tracker.observe(
            transition(
                UnderlyingNetworkConnectivity.ONLINE,
                UnderlyingNetworkConnectivity.CONNECTING
            ),
            nowNanos = 2_000_000_000L
        )
        tracker.recordFailure()
        tracker.observe(
            transition(
                UnderlyingNetworkConnectivity.CONNECTING,
                UnderlyingNetworkConnectivity.ONLINE
            ),
            nowNanos = 2_400_000_000L
        )

        assertEquals(NetworkRecoveryMeasurement(400, 1), tracker.takeCompletedMeasurement())
    }

    @Test
    fun duplicateCapabilitiesDoNotTriggerAnotherRecovery() {
        val reducer = UnderlyingNetworkStateReducer()
        val facts = facts(networkId = 3, isValidated = true)

        reducer.update(facts)
        assertNull(reducer.update(facts))
    }

    @Test
    fun clearForcesANewObservationAfterCallbackRestart() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(networkId = 4, isValidated = true))

        reducer.clear()

        assertEquals(UnderlyingNetworkConnectivity.OFFLINE, reducer.snapshot().connectivity)
        assertEquals(
            UnderlyingNetworkConnectivity.ONLINE,
            reducer.update(facts(networkId = 4, isValidated = true))?.current?.connectivity
        )
    }

    private fun facts(
        networkId: Long,
        isVpn: Boolean = false,
        hasInternet: Boolean = true,
        isValidated: Boolean = false,
        hasCaptivePortal: Boolean = false,
        transportMask: Int = 0,
        lost: Boolean = false
    ) = UnderlyingNetworkFacts(
        networkId = networkId,
        isVpn = isVpn,
        hasInternet = hasInternet,
        isValidated = isValidated,
        hasCaptivePortal = hasCaptivePortal,
        transportMask = transportMask,
        lost = lost
    )

    private fun transition(
        previous: UnderlyingNetworkConnectivity,
        current: UnderlyingNetworkConnectivity
    ) = transition(
        UnderlyingNetworkSnapshot(previous, 0),
        UnderlyingNetworkSnapshot(current, 0)
    )

    private fun transition(
        previous: UnderlyingNetworkSnapshot,
        current: UnderlyingNetworkSnapshot
    ) = UnderlyingNetworkTransition(previous, current)
}
