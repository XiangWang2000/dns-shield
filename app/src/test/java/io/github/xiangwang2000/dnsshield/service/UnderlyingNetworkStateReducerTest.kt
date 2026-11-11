package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class UnderlyingNetworkStateReducerTest {
    @Test
    fun confirmsThePreVpnRouteOnceAfterAndroidSelectsIt() {
        val confirmation = StartupNetworkConfirmation(42L)
        val unknown = UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.UNKNOWN, 1)
        val online = UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 1, selectedNetworkId = 42L)
        assertFalse(confirmation.confirmsFirstRoute(unknown))
        assertFalse(confirmation.confirmsFirstRoute(unknown.copy(selectedNetworkId = 42L)))
        assertTrue(confirmation.confirmsFirstRoute(online))
        assertFalse(confirmation.confirmsFirstRoute(online))
    }

    @Test
    fun keepsTheDebounceAfterAConflictingRouteOrLossOfValidation() {
        val online = UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 1, selectedNetworkId = 42L)
        val changedRoute = StartupNetworkConfirmation(42L)
        val lostValidation = StartupNetworkConfirmation(42L)
        assertFalse(changedRoute.confirmsFirstRoute(online.copy(selectedNetworkId = 7L)))
        assertFalse(changedRoute.confirmsFirstRoute(online))
        assertFalse(lostValidation.confirmsFirstRoute(online.copy(connectivity = UnderlyingNetworkConnectivity.CONNECTING)))
        assertFalse(lostValidation.confirmsFirstRoute(online))
        assertFalse(StartupNetworkConfirmation(null).confirmsFirstRoute(online))
    }

    @Test
    fun ignoresVpnEventsAndReportsNonVpnConnectivity() {
        val reducer = UnderlyingNetworkStateReducer()

        assertNull(reducer.update(facts(networkId = 1, isVpn = true, isValidated = true)))
        assertEquals(
            UnderlyingNetworkSnapshot(
                UnderlyingNetworkConnectivity.UNKNOWN,
                0,
                candidateConnectivity = UnderlyingNetworkConnectivity.OFFLINE
            ),
            reducer.snapshot()
        )

        val connecting = reducer.update(facts(networkId = 2))
        assertEquals(UnderlyingNetworkConnectivity.UNKNOWN, connecting?.current?.connectivity)
        assertEquals(UnderlyingNetworkConnectivity.CONNECTING, connecting?.current?.candidateConnectivity)

        val selectedConnecting = reducer.selectDefaultNetwork(2)
        assertEquals(UnderlyingNetworkConnectivity.CONNECTING, selectedConnecting?.current?.connectivity)

        val online = reducer.update(facts(networkId = 2, isValidated = true))
        assertEquals(UnderlyingNetworkConnectivity.ONLINE, online?.current?.connectivity)
    }

    @Test
    fun reportsCaptivePortalAndReturnsOfflineAfterLastNetworkIsLost() {
        val reducer = UnderlyingNetworkStateReducer()

        val candidatePortal = reducer.update(facts(networkId = 7, hasInternet = false, hasCaptivePortal = true))
        assertEquals(UnderlyingNetworkConnectivity.UNKNOWN, candidatePortal?.current?.connectivity)
        assertFalse(candidatePortal?.effectiveRouteChanged == true)
        assertTrue(candidatePortal?.shouldFenceDnsState == true)

        val portal = reducer.selectDefaultNetwork(7)
        assertEquals(UnderlyingNetworkConnectivity.CAPTIVE_PORTAL, portal?.current?.connectivity)

        val lost = reducer.update(facts(networkId = 7, lost = true))
        assertEquals(UnderlyingNetworkConnectivity.UNKNOWN, lost?.current?.connectivity)

        val offline = reducer.clearSelectedDefaultNetwork(7)
        assertEquals(UnderlyingNetworkConnectivity.OFFLINE, offline?.current?.connectivity)
        assertEquals(0, offline?.current?.networkCount)
    }

    @Test
    fun selectedCaptivePortalDoesNotAppearOnlineBecauseAnotherCandidateIsValidated() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(networkId = 1, isValidated = true, transportMask = 1))
        reducer.update(facts(networkId = 2, hasInternet = false, hasCaptivePortal = true, transportMask = 2))

        val selectedPortal = reducer.selectDefaultNetwork(2)

        assertEquals(UnderlyingNetworkConnectivity.CAPTIVE_PORTAL, selectedPortal?.current?.connectivity)
        assertEquals(UnderlyingNetworkConnectivity.ONLINE, selectedPortal?.current?.candidateConnectivity)
        assertTrue(selectedPortal?.effectiveRouteChanged == true)
        assertTrue(selectedPortal.shouldFenceDnsState)

        val selectedCapabilities = reducer.update(facts(networkId = 2, isValidated = false, transportMask = 2))
        assertEquals(UnderlyingNetworkConnectivity.CONNECTING, selectedCapabilities?.current?.connectivity)
        assertTrue(selectedCapabilities?.effectiveRouteChanged == true)

        val selectedLost = reducer.update(facts(networkId = 2, lost = true))
        assertEquals(UnderlyingNetworkConnectivity.UNKNOWN, selectedLost?.current?.connectivity)
        assertTrue(selectedLost?.effectiveRouteChanged == true)

        val replacement = reducer.selectDefaultNetwork(1)
        assertEquals(UnderlyingNetworkConnectivity.ONLINE, replacement?.current?.connectivity)
        assertTrue(replacement?.effectiveRouteChanged == true)
    }

    @Test
    fun reportsNetworkIdentityChangesEvenWhenConnectivityRemainsOnline() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(networkId = 1, isValidated = true))
        reducer.selectDefaultNetwork(1)
        val secondNetwork = reducer.update(facts(networkId = 2, isValidated = true, transportMask = 2))

        assertEquals(
            UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 2, 1, 0),
            secondNetwork?.current
        )
        assertFalse(secondNetwork?.effectiveRouteChanged == true)
        assertFalse(secondNetwork?.shouldFenceDnsState == true)

        val selectedSecond = reducer.selectDefaultNetwork(2)
        assertEquals(UnderlyingNetworkConnectivity.ONLINE, selectedSecond?.current?.connectivity)
        assertTrue(selectedSecond?.effectiveRouteChanged == true)

        val lostFirstNetwork = reducer.update(facts(networkId = 1, lost = true))
        assertEquals(
            UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 1, 2, 2),
            lostFirstNetwork?.current
        )
        assertFalse(lostFirstNetwork?.effectiveRouteChanged == true)
        assertFalse(lostFirstNetwork?.shouldFenceDnsState == true)
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
            UnderlyingNetworkSnapshot(
                UnderlyingNetworkConnectivity.UNKNOWN,
                2,
                null,
                1,
                UnderlyingNetworkConnectivity.ONLINE
            ),
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
            UnderlyingNetworkSnapshot(
                UnderlyingNetworkConnectivity.UNKNOWN,
                1,
                null,
                0,
                UnderlyingNetworkConnectivity.ONLINE
            ),
            reducer.snapshot()
        )
    }

    @Test
    fun selectorAndCandidateCallbacksMayArriveInEitherOrder() {
        val selectorFirst = UnderlyingNetworkStateReducer()
        selectorFirst.selectDefaultNetwork(51)
        selectorFirst.update(facts(networkId = 51, isValidated = true, transportMask = 1))

        val candidateFirst = UnderlyingNetworkStateReducer()
        candidateFirst.update(facts(networkId = 51, isValidated = true, transportMask = 1))
        candidateFirst.selectDefaultNetwork(51)

        assertEquals(UnderlyingNetworkSnapshot(UnderlyingNetworkConnectivity.ONLINE, 1, 51, 1), selectorFirst.snapshot())
        assertEquals(selectorFirst.snapshot(), candidateFirst.snapshot())
    }

    @Test
    fun ambiguousRouteCandidateChangeFencesEvenWhenVisibleSnapshotIsUnchanged() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(networkId = 61, isValidated = true, transportMask = 1))
        reducer.update(facts(networkId = 62, isValidated = true, transportMask = 1))
        reducer.selectDefaultNetworkByTransportMask(1)
        val before = reducer.snapshot()

        val changedCandidate = reducer.update(facts(networkId = 61, isValidated = false, transportMask = 1))

        assertEquals(before, changedCandidate?.current)
        assertFalse(changedCandidate?.effectiveRouteChanged == true)
        assertTrue(changedCandidate?.shouldFenceDnsState == true)
        assertNull(reducer.update(facts(networkId = 61, isValidated = false, transportMask = 1)))
    }

    @Test
    fun nonSelectedCandidateChurnDoesNotApplyDnsInvalidationEffects() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(networkId = 71, isValidated = true, transportMask = 1))
        val selected = reducer.selectDefaultNetwork(71)
        assertNull(reducer.selectDefaultNetwork(71))
        var generation = 0
        var cacheClears = 0
        var leaderCancellations = 0
        var baseClientResets = 0
        val primaryResolver = "10.0.0.1"

        assertTrue(selected!!.runIfDnsStateFenceRequired {
            generation++
            cacheClears++
            leaderCancellations++
            baseClientResets++
        })

        val candidateEvents = listOf(
            facts(networkId = 72, isValidated = true, transportMask = 2),
            facts(networkId = 72, isValidated = false, transportMask = 2),
            facts(networkId = 72, lost = true, transportMask = 2),
            facts(networkId = 72, isValidated = true, transportMask = 2)
        )
        candidateEvents.forEach { facts ->
            val transition = reducer.update(facts)
            if (transition != null) {
                assertFalse(transition.runIfDnsStateFenceRequired {
                    generation++
                    cacheClears++
                    leaderCancellations++
                    baseClientResets++
                })
            }
            assertEquals(71, reducer.snapshot().selectedNetworkId)
            assertEquals(UnderlyingNetworkConnectivity.ONLINE, reducer.snapshot().connectivity)
        }
        repeat(32) { index ->
            val transition = reducer.update(
                facts(networkId = 72, isValidated = index % 2 == 0, transportMask = 2)
            )
            assertFalse(transition?.shouldFenceDnsState == true)
            assertEquals(71, reducer.snapshot().selectedNetworkId)
            assertEquals(UnderlyingNetworkConnectivity.ONLINE, reducer.snapshot().connectivity)
        }

        assertEquals(1, generation)
        assertEquals(1, cacheClears)
        assertEquals(1, leaderCancellations)
        assertEquals(1, baseClientResets)
        assertEquals("10.0.0.1", primaryResolver)
    }

    @Test
    fun debounceAndCallbackGuardsPreservePendingRouteWorkAndRejectStoppedCallbacks() {
        assertTrue(shouldReplaceNetworkStatusDebounce(networkChangePending = false, incomingRouteChange = false))
        assertFalse(shouldReplaceNetworkStatusDebounce(networkChangePending = true, incomingRouteChange = false))
        assertTrue(shouldReplaceNetworkStatusDebounce(networkChangePending = true, incomingRouteChange = true))

        assertTrue(isCurrentUnderlyingNetworkCallback(9, 9, 9, isVpnRunning = true))
        assertFalse(isCurrentUnderlyingNetworkCallback(8, 9, 8, isVpnRunning = true))
        assertFalse(isCurrentUnderlyingNetworkCallback(9, 9, null, isVpnRunning = true))
        assertFalse(isCurrentUnderlyingNetworkCallback(9, 9, 9, isVpnRunning = false))
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

        assertEquals(UnderlyingNetworkConnectivity.UNKNOWN, reducer.snapshot().connectivity)
        assertEquals(UnderlyingNetworkConnectivity.OFFLINE, reducer.snapshot().candidateConnectivity)
        assertEquals(
            UnderlyingNetworkConnectivity.UNKNOWN,
            reducer.update(facts(networkId = 4, isValidated = true))?.current?.connectivity
        )
        assertEquals(
            UnderlyingNetworkConnectivity.ONLINE,
            reducer.selectDefaultNetwork(4)?.current?.connectivity
        )
    }

    @Test
    fun selectedSameNetworkIpContextChangesFenceDnsWithoutChangingConnectivity() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(1, isValidated = true))
        reducer.selectDefaultNetwork(1)
        assertNull(reducer.updateIpContext(1, ipContext()))
        val before = reducer.snapshot()
        val changes = listOf(
            ipContext(prefix = "2001:db8:64::/96"),
            ipContext(prefix = "2001:db8:64::/96", address = "2001:db8:2::2/64"),
            ipContext(prefix = "2001:db8:64::/96", address = "2001:db8:2::2/64", route = "::/0 via fe80::2"),
            ipContext(prefix = "2001:db8:64::/96", address = "2001:db8:2::2/64", route = "::/0 via fe80::2", dns = "2001:db8::54")
        )
        for (context in changes) {
            val transition = requireNotNull(reducer.updateIpContext(1, context))
            assertEquals(before, transition.previous)
            assertEquals(before, transition.current)
            var fenced = false
            assertTrue(transition.runIfDnsStateFenceRequired { fenced = true })
            assertTrue(fenced)
            assertNull(reducer.updateIpContext(1, context))
        }
    }

    @Test
    fun selectedPrivateDnsChangesFenceDnsWithoutChangingConnectivity() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(1, isValidated = true))
        reducer.selectDefaultNetwork(1)
        fun privateDnsContext(active: Boolean, serverName: String? = null) =
            UnderlyingNetworkIpContext.of(
                emptyList(), emptyList(), listOf("192.0.2.53"),
                privateDnsActive = active, privateDnsServerName = serverName
            )

        assertNull(reducer.updateIpContext(1, privateDnsContext(false)))
        val opportunistic = requireNotNull(reducer.updateIpContext(1, privateDnsContext(true)))
        assertTrue(opportunistic.shouldFenceDnsState)
        assertEquals(opportunistic.previous, opportunistic.current)

        val strict = privateDnsContext(true, "resolver.example")
        assertTrue(requireNotNull(reducer.updateIpContext(1, strict)).shouldFenceDnsState)
        assertNull(reducer.updateIpContext(1, strict))
    }

    @Test
    fun unselectedIpChangesAreStoredWithoutFencingAndSelectionStillFences() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(1, isValidated = true))
        reducer.update(facts(2, isValidated = true))
        reducer.selectDefaultNetwork(1)
        assertNull(reducer.updateIpContext(2, ipContext()))
        assertNull(reducer.updateIpContext(2, ipContext(prefix = "2001:db8:64::/96")))
        assertEquals(1L, reducer.snapshot().selectedNetworkId)
        assertTrue(reducer.selectDefaultNetwork(2)?.shouldFenceDnsState == true)
        assertNull(reducer.updateIpContext(2, ipContext(prefix = "2001:db8:64::/96")))
        assertTrue(reducer.updateIpContext(2, ipContext())?.shouldFenceDnsState == true)
    }

    @Test
    fun ipContextBeforeCapabilitiesOrSelectionIsAnInitialBaseline() {
        val reducer = UnderlyingNetworkStateReducer()
        assertNull(reducer.updateIpContext(9, ipContext()))
        reducer.update(facts(9, isValidated = true))
        assertTrue(reducer.selectDefaultNetwork(9)?.shouldFenceDnsState == true)
        assertNull(reducer.updateIpContext(9, ipContext()))
        assertTrue(reducer.updateIpContext(9, ipContext(prefix = null))?.shouldFenceDnsState == true)
    }

    @Test
    fun normalizedIpContextsIgnoreOrderingAndDoNotRetainMutableInputLists() {
        val addresses = mutableListOf("2001:db8::2/64", "192.0.2.2/24")
        val context = UnderlyingNetworkIpContext.of(addresses, listOf("b", "a"), listOf("::1", "::1"))
        addresses.clear()
        assertEquals(context, UnderlyingNetworkIpContext.of(
            listOf("192.0.2.2/24", "2001:db8::2/64"), listOf("a", "b", "a"), listOf("::1")
        ))
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(1, isValidated = true))
        reducer.selectDefaultNetwork(1)
        assertNull(reducer.updateIpContext(1, context))
        assertNull(reducer.updateIpContext(1, UnderlyingNetworkIpContext.of(
            listOf("2001:db8::2/64", "192.0.2.2/24"), listOf("b", "a"), listOf("::1")
        )))
    }

    @Test
    fun lostNetworksAndCallbackRestartDiscardIpContextBaselines() {
        val reducer = UnderlyingNetworkStateReducer()
        reducer.update(facts(3, isValidated = true))
        reducer.selectDefaultNetwork(3)
        reducer.updateIpContext(3, ipContext())
        reducer.update(facts(3, lost = true))
        reducer.update(facts(3, isValidated = true))
        assertNull(reducer.updateIpContext(3, ipContext(prefix = null)))
        reducer.clear()
        reducer.update(facts(3, isValidated = true))
        reducer.selectDefaultNetwork(3)
        assertNull(reducer.updateIpContext(3, ipContext()))
    }

    private fun ipContext(
        prefix: String? = "64:ff9b::/96",
        address: String = "2001:db8:1::2/64",
        route: String = "::/0 via fe80::1",
        dns: String = "2001:db8::53"
    ) = UnderlyingNetworkIpContext.of(listOf(address), listOf(route), listOf(dns), prefix)

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
