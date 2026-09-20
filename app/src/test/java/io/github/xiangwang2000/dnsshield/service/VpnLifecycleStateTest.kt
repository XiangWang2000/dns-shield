package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class VpnLifecycleStateTest {
    @Test
    fun onlyStoppedOrFailedSessionsCanStart() {
        assertTrue(VpnLifecycleState.STOPPED.canStart)
        assertTrue(VpnLifecycleState.FAILED.canStart)
        assertFalse(VpnLifecycleState.STARTING.canStart)
        assertFalse(VpnLifecycleState.RUNNING.canStart)
        assertFalse(VpnLifecycleState.STOPPING.canStart)
    }

    @Test
    fun toggleActionMatchesTheReportedLifecycleState() {
        assertEquals(VpnToggleAction.START, VpnLifecycleState.STOPPED.toggleAction())
        assertEquals(VpnToggleAction.START, VpnLifecycleState.FAILED.toggleAction())
        assertEquals(VpnToggleAction.STOP, VpnLifecycleState.STARTING.toggleAction())
        assertEquals(VpnToggleAction.STOP, VpnLifecycleState.RUNNING.toggleAction())
        assertEquals(VpnToggleAction.NONE, VpnLifecycleState.STOPPING.toggleAction())
    }

    @Test
    fun stopRequestInvalidatesAnInProgressStartup() {
        val requests = VpnLifecycleRequestTracker()
        val startup = requests.nextRequest()

        val stop = requests.nextRequest()

        assertFalse(requests.isCurrent(startup))
        assertTrue(requests.isCurrent(stop))
    }

    @Test
    fun laterStartRequestSupersedesAnEarlierStopRequest() {
        val requests = VpnLifecycleRequestTracker()
        val startup = requests.nextRequest()
        val stop = requests.nextRequest()

        val laterStart = requests.nextRequest()

        assertFalse(requests.isCurrent(startup))
        assertFalse(requests.isCurrent(stop))
        assertTrue(requests.isCurrent(laterStart))
    }

    @Test
    fun serviceDestructionPreservesFailedStateForRetry() {
        assertEquals(VpnLifecycleState.FAILED, VpnLifecycleState.FAILED.stateAfterServiceDestroy())
        assertEquals(VpnLifecycleState.STOPPED, VpnLifecycleState.RUNNING.stateAfterServiceDestroy())
    }
}
