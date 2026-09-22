package io.github.xiangwang2000.dnsshield.service

import android.content.SharedPreferences

internal const val VPN_SERVICE_PREFERENCES = "vpn_service_state"
internal const val VPN_DESIRED_ENABLED_KEY = "desired_enabled"
internal const val VPN_EXPLICIT_CHOICE_KEY = "has_explicit_choice"

/**
 * The last explicit user choice that the service must preserve across process
 * recreation. A system Always-on start is also allowed before the app has a
 * recorded explicit choice; an explicit stop or revoke remains authoritative.
 */
internal data class VpnUserIntentState(
    val desiredEnabled: Boolean = false,
    val hasExplicitChoice: Boolean = false
) {
    fun afterExplicitStart(): VpnUserIntentState = copy(
        desiredEnabled = true,
        hasExplicitChoice = true
    )

    fun afterExplicitStop(): VpnUserIntentState = copy(
        desiredEnabled = false,
        hasExplicitChoice = true
    )

    fun afterAuthorizationRevoke(): VpnUserIntentState = copy(
        desiredEnabled = false,
        hasExplicitChoice = true
    )

    fun shouldRecoverFromSystemStart(systemAlwaysOn: Boolean): Boolean =
        desiredEnabled || (systemAlwaysOn && !hasExplicitChoice)

    fun shouldUseStickyServiceStart(systemAlwaysOn: Boolean): Boolean =
        desiredEnabled || (systemAlwaysOn && !hasExplicitChoice)
}

internal class VpnUserIntentStore(private val preferences: SharedPreferences) {
    fun snapshot(): VpnUserIntentState = VpnUserIntentState(
        desiredEnabled = preferences.getBoolean(VPN_DESIRED_ENABLED_KEY, false),
        hasExplicitChoice = preferences.getBoolean(VPN_EXPLICIT_CHOICE_KEY, false)
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
            .putBoolean(VPN_DESIRED_ENABLED_KEY, state.desiredEnabled)
            .putBoolean(VPN_EXPLICIT_CHOICE_KEY, state.hasExplicitChoice)
            .apply()
    }
}
