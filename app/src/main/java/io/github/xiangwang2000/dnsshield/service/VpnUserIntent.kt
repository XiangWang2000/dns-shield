package io.github.xiangwang2000.dnsshield.service

import android.content.SharedPreferences

/**
 * The last explicit user choice that the service must preserve across process
 * recreation. System recovery is allowed only while this choice is enabled.
 */
internal data class VpnUserIntentState(val desiredEnabled: Boolean = false) {
    fun afterExplicitStart(): VpnUserIntentState = copy(desiredEnabled = true)

    fun afterExplicitStop(): VpnUserIntentState = copy(desiredEnabled = false)

    fun afterAuthorizationRevoke(): VpnUserIntentState = copy(desiredEnabled = false)

    fun shouldRecoverFromSystemStart(): Boolean = desiredEnabled

    fun shouldUseStickyServiceStart(): Boolean = desiredEnabled
}

internal class VpnUserIntentStore(private val preferences: SharedPreferences) {
    fun snapshot(): VpnUserIntentState = VpnUserIntentState(
        desiredEnabled = preferences.getBoolean(KEY_DESIRED_ENABLED, false)
    )

    fun markExplicitStart() {
        save(snapshot().afterExplicitStart())
    }

    fun markExplicitStop() {
        save(snapshot().afterExplicitStop())
    }

    fun markAuthorizationRevoke() {
        save(snapshot().afterAuthorizationRevoke())
    }

    private fun save(state: VpnUserIntentState) {
        preferences.edit()
            .putBoolean(KEY_DESIRED_ENABLED, state.desiredEnabled)
            .apply()
    }

    private companion object {
        const val KEY_DESIRED_ENABLED = "desired_enabled"
    }
}
