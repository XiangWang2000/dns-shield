package io.github.xiangwang2000.dnsshield.service

import android.content.SharedPreferences
import android.util.Log
import java.util.IdentityHashMap
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch

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

    fun shouldAcceptStartRequest(isCurrentRequest: Boolean, systemAlwaysOn: Boolean): Boolean =
        isCurrentRequest && shouldRecoverFromSystemStart(systemAlwaysOn)

    fun shouldUseStickyServiceStart(systemAlwaysOn: Boolean): Boolean =
        desiredEnabled || (systemAlwaysOn && !hasExplicitChoice)
}

internal enum class VpnUserIntentWriteKind {
    EXPLICIT_START,
    EXPLICIT_STOP,
    AUTHORIZATION_REVOKE,
    FAILED_START_FALLBACK
}

internal data class VpnUserIntentWrite(
    val revision: Long,
    val state: VpnUserIntentState,
    val kind: VpnUserIntentWriteKind,
    internal val durableCompletion: CompletableDeferred<Boolean>
)

private data class VpnUserIntentWriteRequest(
    val write: VpnUserIntentWrite,
    val writer: suspend (VpnUserIntentState) -> Boolean
)

/** Process-wide ordering survives a service actor being cancelled during shutdown. */
private object VpnUserIntentPersistence {
    private const val TAG = "VpnUserIntent"
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val registryLock = Any()
    // This app uses one intent preferences file; keep its coordinator for the process lifetime.
    private val coordinators = IdentityHashMap<SharedPreferences, Coordinator>()

    fun coordinator(
        preferences: SharedPreferences,
        initialState: VpnUserIntentState
    ): Coordinator = synchronized(registryLock) {
        coordinators[preferences] ?: Coordinator(initialState).also {
            coordinators[preferences] = it
        }
    }

    class Coordinator(initialState: VpnUserIntentState) {
        private val lock = Any()
        private val writes = Channel<VpnUserIntentWriteRequest>(Channel.UNLIMITED)
        private var requestedState = initialState
        private var latestRevision = 0L

        init {
            scope.launch {
                for (request in writes) {
                    try {
                        val persisted = request.writer(request.write.state)
                        if (!persisted) {
                            reportFailure("Commit returned false for revision ${request.write.revision}")
                        }
                        request.write.durableCompletion.complete(persisted)
                    } catch (exception: Exception) {
                        reportFailure("Commit failed for revision ${request.write.revision}", exception)
                        request.write.durableCompletion.completeExceptionally(exception)
                    }
                }
            }
        }

        fun snapshot(): VpnUserIntentState = synchronized(lock) { requestedState }

        fun stage(
            kind: VpnUserIntentWriteKind,
            writer: suspend (VpnUserIntentState) -> Boolean,
            transition: (VpnUserIntentState) -> VpnUserIntentState
        ): VpnUserIntentWrite = synchronized(lock) {
            enqueue(kind, transition(requestedState), writer)
        }

        fun stageFailedStartFallback(
            failedStart: VpnUserIntentWrite,
            writer: suspend (VpnUserIntentState) -> Boolean
        ): VpnUserIntentWrite? = synchronized(lock) {
            if (failedStart.kind != VpnUserIntentWriteKind.EXPLICIT_START ||
                latestRevision != failedStart.revision || requestedState != failedStart.state
            ) return@synchronized null

            enqueue(
                VpnUserIntentWriteKind.FAILED_START_FALLBACK,
                failedStart.state.afterExplicitStop(),
                writer
            )
        }

        private fun enqueue(
            kind: VpnUserIntentWriteKind,
            state: VpnUserIntentState,
            writer: suspend (VpnUserIntentState) -> Boolean
        ): VpnUserIntentWrite {
            val write = VpnUserIntentWrite(
                revision = latestRevision + 1,
                state = state,
                kind = kind,
                durableCompletion = CompletableDeferred()
            )
            check(writes.trySend(VpnUserIntentWriteRequest(write, writer)).isSuccess) {
                "Intent persistence worker is unavailable"
            }
            latestRevision = write.revision
            requestedState = state
            return write
        }
    }

    private fun reportFailure(message: String, exception: Exception? = null) {
        try {
            if (exception == null) Log.e(TAG, message) else Log.e(TAG, message, exception)
        } catch (_: RuntimeException) {
            // Android's Log methods are unavailable in local JVM tests.
        }
    }
}

internal class VpnUserIntentStore(
    private val preferences: SharedPreferences,
    private val writeState: suspend (VpnUserIntentState) -> Boolean = { state ->
        preferences.edit()
            .putBoolean(VPN_DESIRED_ENABLED_KEY, state.desiredEnabled)
            .putBoolean(VPN_EXPLICIT_CHOICE_KEY, state.hasExplicitChoice)
            .commit()
    }
) {
    private val coordinator = VpnUserIntentPersistence.coordinator(preferences, readPreferences())

    fun snapshot(): VpnUserIntentState = coordinator.snapshot()

    fun stageExplicitStart(): VpnUserIntentWrite =
        stage(VpnUserIntentWriteKind.EXPLICIT_START) { it.afterExplicitStart() }

    fun stageExplicitStop(): VpnUserIntentWrite =
        stage(VpnUserIntentWriteKind.EXPLICIT_STOP) { it.afterExplicitStop() }

    fun stageAuthorizationRevoke(): VpnUserIntentWrite =
        stage(VpnUserIntentWriteKind.AUTHORIZATION_REVOKE) { it.afterAuthorizationRevoke() }

    /** True means the accepted write reached its durable completion point. */
    suspend fun persist(write: VpnUserIntentWrite): Boolean = write.durableCompletion.await()

    /** Fail closed only while this failed START remains the latest requested operation. */
    fun stageFailedStartFallback(failedStart: VpnUserIntentWrite): VpnUserIntentWrite? =
        coordinator.stageFailedStartFallback(failedStart, writeState)

    private fun stage(
        kind: VpnUserIntentWriteKind,
        transition: (VpnUserIntentState) -> VpnUserIntentState
    ): VpnUserIntentWrite = coordinator.stage(kind, writeState, transition)

    private fun readPreferences() = VpnUserIntentState(
        desiredEnabled = preferences.getBoolean(VPN_DESIRED_ENABLED_KEY, false),
        hasExplicitChoice = preferences.getBoolean(VPN_EXPLICIT_CHOICE_KEY, false)
    )
}
