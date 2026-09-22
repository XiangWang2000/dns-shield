package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class VpnUserIntentTest {
    @Test
    fun explicitStartEnablesSystemRecoveryAndStickyRestart() {
        val state = VpnUserIntentState().afterExplicitStart()

        assertTrue(state.desiredEnabled)
        assertTrue(state.shouldRecoverFromSystemStart())
        assertTrue(state.shouldUseStickyServiceStart())
    }

    @Test
    fun explicitStopSuppressesNullIntentRecoveryAndStickyRestart() {
        val state = VpnUserIntentState(true).afterExplicitStop()

        assertFalse(state.desiredEnabled)
        assertFalse(state.shouldRecoverFromSystemStart())
        assertFalse(state.shouldUseStickyServiceStart())
    }

    @Test
    fun authorizationRevokeSuppressesRecoveryUntilAnExplicitStart() {
        val revoked = VpnUserIntentState(true).afterAuthorizationRevoke()

        assertFalse(revoked.shouldRecoverFromSystemStart())
        assertTrue(revoked.afterExplicitStart().shouldRecoverFromSystemStart())
    }
}
