package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class VpnUserIntentTest {
    @Test
    fun explicitStartEnablesSystemRecoveryAndStickyRestart() {
        val state = VpnUserIntentState().afterExplicitStart()

        assertTrue(state.desiredEnabled)
        assertTrue(state.hasExplicitChoice)
        assertTrue(state.shouldRecoverFromSystemStart(systemAlwaysOn = false))
        assertTrue(state.shouldUseStickyServiceStart(systemAlwaysOn = false))
    }

    @Test
    fun explicitStopSuppressesNullIntentRecoveryAndStickyRestart() {
        val state = VpnUserIntentState(true).afterExplicitStop()

        assertFalse(state.desiredEnabled)
        assertTrue(state.hasExplicitChoice)
        assertFalse(state.shouldRecoverFromSystemStart(systemAlwaysOn = true))
        assertFalse(state.shouldUseStickyServiceStart(systemAlwaysOn = true))
    }

    @Test
    fun authorizationRevokeSuppressesRecoveryUntilAnExplicitStart() {
        val revoked = VpnUserIntentState(true).afterAuthorizationRevoke()

        assertFalse(revoked.shouldRecoverFromSystemStart(systemAlwaysOn = true))
        assertTrue(revoked.afterExplicitStart().shouldRecoverFromSystemStart(systemAlwaysOn = true))
    }

    @Test
    fun systemAlwaysOnCanRecoverBeforeTheFirstExplicitAppChoice() {
        val untouched = VpnUserIntentState()

        assertTrue(untouched.shouldRecoverFromSystemStart(systemAlwaysOn = true))
        assertTrue(untouched.shouldUseStickyServiceStart(systemAlwaysOn = true))
        assertFalse(untouched.shouldRecoverFromSystemStart(systemAlwaysOn = false))
    }
}
