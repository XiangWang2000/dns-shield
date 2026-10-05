package io.github.xiangwang2000.dnsshield.service

import android.content.SharedPreferences
import java.lang.reflect.Proxy
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
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

    @Test
    fun stopIsStillPersistableAfterNewerRestartRequestAndBlocksBothRequests() = runBlocking {
        val inMemory = mutableMapOf(
            VPN_DESIRED_ENABLED_KEY to true,
            VPN_EXPLICIT_CHOICE_KEY to true
        )
        val onDisk = inMemory.toMutableMap()
        val preferences = recordingPreferences(inMemory, onDisk, mutableListOf(true))
        val store = VpnUserIntentStore(preferences)
        val requests = VpnLifecycleRequestTracker()
        val oldStart = requests.nextRequest()
        val stopWrite = store.stageExplicitStop()
        val restart = requests.nextRequest()

        assertTrue(requests.isCurrent(restart))
        assertFalse(
            store.snapshot().shouldAcceptStartRequest(
                isCurrentRequest = requests.isCurrent(restart),
                systemAlwaysOn = true
            )
        )
        assertFalse(
            store.snapshot().shouldAcceptStartRequest(
                isCurrentRequest = requests.isCurrent(oldStart),
                systemAlwaysOn = true
            )
        )
        assertTrue(store.persist(stopWrite), "Queued STOP still reaches its durable completion point")
        assertEquals(false, onDisk[VPN_DESIRED_ENABLED_KEY])
    }

    @Test
    fun explicitStopPersistsBothIntentValuesBeforeReturningTrue(): Unit = runBlocking {
        val inMemory = mutableMapOf(
            VPN_DESIRED_ENABLED_KEY to true,
            VPN_EXPLICIT_CHOICE_KEY to false
        )
        val onDisk = inMemory.toMutableMap()
        val preferences = recordingPreferences(inMemory, onDisk, mutableListOf(true))
        val store = VpnUserIntentStore(preferences)
        val write = store.stageExplicitStop()

        assertFalse(store.snapshot().desiredEnabled)
        assertTrue(store.persist(write))
        assertEquals(false, inMemory[VPN_DESIRED_ENABLED_KEY])
        assertEquals(true, inMemory[VPN_EXPLICIT_CHOICE_KEY])
        assertEquals(inMemory, onDisk)
    }

    @Test
    fun failedStartFallbackCanOnlyFailClosedInTheCurrentProcess(): Unit = runBlocking {
        val inMemory = mutableMapOf(
            VPN_DESIRED_ENABLED_KEY to false,
            VPN_EXPLICIT_CHOICE_KEY to false
        )
        val onDisk = inMemory.toMutableMap()
        val preferences = recordingPreferences(inMemory, onDisk, mutableListOf(false, false))
        val store = VpnUserIntentStore(preferences)
        val start = store.stageExplicitStart()

        assertFalse(store.persist(start))
        val fallback = store.stageFailedStartFallback(start)
        assertTrue(fallback != null)
        assertFalse(store.persist(fallback))

        val state = store.snapshot()
        assertFalse(state.desiredEnabled)
        assertTrue(state.hasExplicitChoice)
        assertFalse(state.shouldRecoverFromSystemStart(systemAlwaysOn = true))
        assertEquals(false, inMemory[VPN_DESIRED_ENABLED_KEY])
        assertEquals(true, inMemory[VPN_EXPLICIT_CHOICE_KEY])
        assertEquals(false, onDisk[VPN_DESIRED_ENABLED_KEY])
        assertEquals(false, onDisk[VPN_EXPLICIT_CHOICE_KEY])

        val processRestarted = VpnUserIntentStore(
            recordingPreferences(onDisk.toMutableMap(), onDisk, mutableListOf())
        )
        assertTrue(
            processRestarted.snapshot().shouldRecoverFromSystemStart(systemAlwaysOn = true),
            "If both commits fail, a fresh process may read the old Always-on-compatible disk values"
        )
    }

    @Test
    fun failedStopAndRevokeStillStageFailClosedIntent(): Unit = runBlocking {
        val inMemory = mutableMapOf(
            VPN_DESIRED_ENABLED_KEY to true,
            VPN_EXPLICIT_CHOICE_KEY to true
        )
        val onDisk = inMemory.toMutableMap()
        val preferences = recordingPreferences(inMemory, onDisk, mutableListOf(false, false))
        val store = VpnUserIntentStore(preferences)

        assertFalse(store.persist(store.stageExplicitStop()))
        assertFalse(store.snapshot().desiredEnabled)
        assertFalse(store.snapshot().shouldRecoverFromSystemStart(systemAlwaysOn = true))

        assertFalse(store.persist(store.stageAuthorizationRevoke()))
        assertFalse(store.snapshot().desiredEnabled)
        assertFalse(store.snapshot().shouldRecoverFromSystemStart(systemAlwaysOn = true))
        assertEquals(true, onDisk[VPN_DESIRED_ENABLED_KEY])
        assertEquals(true, onDisk[VPN_EXPLICIT_CHOICE_KEY])

        val processRestarted = VpnUserIntentStore(
            recordingPreferences(onDisk.toMutableMap(), onDisk, mutableListOf())
        )
        assertTrue(
            processRestarted.snapshot().shouldRecoverFromSystemStart(systemAlwaysOn = true),
            "A failed STOP/revoke commit cannot claim to suppress recovery after process death"
        )
    }

    @Test
    fun stagedStopSurvivesCancellationOfTheStartPersistenceWaiter(): Unit = runBlocking {
        val inMemory = mutableMapOf(
            VPN_DESIRED_ENABLED_KEY to false,
            VPN_EXPLICIT_CHOICE_KEY to false
        )
        val onDisk = inMemory.toMutableMap()
        val startWriterEntered = CompletableDeferred<Unit>()
        val finishStartWrite = CompletableDeferred<Boolean>()
        val preferences = recordingPreferences(inMemory, onDisk, mutableListOf())
        val store = VpnUserIntentStore(preferences) { state ->
            inMemory[VPN_DESIRED_ENABLED_KEY] = state.desiredEnabled
            inMemory[VPN_EXPLICIT_CHOICE_KEY] = state.hasExplicitChoice
            if (state.desiredEnabled) {
                startWriterEntered.complete(Unit)
                val result = finishStartWrite.await()
                if (result) onDisk.putAll(inMemory)
                result
            } else {
                onDisk.putAll(inMemory)
                true
            }
        }

        val start = store.stageExplicitStart()
        val waiter = launch { store.persist(start) }
        startWriterEntered.await()
        waiter.cancelAndJoin()

        val stop = store.stageExplicitStop()
        finishStartWrite.complete(true)

        assertTrue(store.persist(stop))
        assertEquals(false, onDisk[VPN_DESIRED_ENABLED_KEY])
        assertEquals(true, onDisk[VPN_EXPLICIT_CHOICE_KEY])
    }

    @Test
    fun storesShareRequestedStateAndKeepAnOldFailedStartFallbackBehindANewerStart(): Unit = runBlocking {
        val inMemory = mutableMapOf(
            VPN_DESIRED_ENABLED_KEY to false,
            VPN_EXPLICIT_CHOICE_KEY to false
        )
        val onDisk = inMemory.toMutableMap()
        val startWriterEntered = CompletableDeferred<Unit>()
        val finishOldStartWrite = CompletableDeferred<Boolean>()
        val preferences = recordingPreferences(inMemory, onDisk, mutableListOf(true))
        val firstStore = VpnUserIntentStore(preferences) { state ->
            inMemory[VPN_DESIRED_ENABLED_KEY] = state.desiredEnabled
            inMemory[VPN_EXPLICIT_CHOICE_KEY] = state.hasExplicitChoice
            startWriterEntered.complete(Unit)
            val result = finishOldStartWrite.await()
            if (result) onDisk.putAll(inMemory)
            result
        }
        val secondStore = VpnUserIntentStore(preferences)

        val oldStart = firstStore.stageExplicitStart()
        val oldStartPersist = async { firstStore.persist(oldStart) }
        startWriterEntered.await()
        val newStart = secondStore.stageExplicitStart()

        assertTrue(firstStore.snapshot().desiredEnabled)
        assertNull(firstStore.stageFailedStartFallback(oldStart))
        finishOldStartWrite.complete(false)

        assertFalse(oldStartPersist.await())
        assertTrue(secondStore.persist(newStart))
        assertEquals(true, onDisk[VPN_DESIRED_ENABLED_KEY])
        assertEquals(true, onDisk[VPN_EXPLICIT_CHOICE_KEY])
    }

    @Test
    fun delayedStartThenStopOrRevokeFinishesWithDurableStop(): Unit = runBlocking {
        for (revoke in listOf(false, true)) {
            val inMemory = mutableMapOf(
                VPN_DESIRED_ENABLED_KEY to false,
                VPN_EXPLICIT_CHOICE_KEY to false
            )
            val onDisk = inMemory.toMutableMap()
            val startWriterEntered = CompletableDeferred<Unit>()
            val finishStartWrite = CompletableDeferred<Boolean>()
            val preferences = recordingPreferences(inMemory, onDisk, mutableListOf())
            val store = VpnUserIntentStore(preferences) { state ->
                inMemory[VPN_DESIRED_ENABLED_KEY] = state.desiredEnabled
                inMemory[VPN_EXPLICIT_CHOICE_KEY] = state.hasExplicitChoice
                if (state.desiredEnabled) {
                    startWriterEntered.complete(Unit)
                    val result = finishStartWrite.await()
                    if (result) onDisk.putAll(inMemory)
                    result
                } else {
                    onDisk.putAll(inMemory)
                    true
                }
            }

            val start = store.stageExplicitStart()
            val startPersist = async { store.persist(start) }
            startWriterEntered.await()

            val stop = if (revoke) store.stageAuthorizationRevoke() else store.stageExplicitStop()
            assertFalse(store.snapshot().desiredEnabled)
            assertFalse(
                store.snapshot().shouldAcceptStartRequest(
                    isCurrentRequest = true,
                    systemAlwaysOn = true
                )
            )
            assertNull(store.stageFailedStartFallback(start))

            // The lifecycle actor finishes the in-flight START write before persisting queued STOP/revoke.
            val stopPersist = async {
                assertTrue(startPersist.await())
                store.persist(stop)
            }
            finishStartWrite.complete(true)

            assertTrue(startPersist.await())
            assertTrue(stopPersist.await())
            assertEquals(false, onDisk[VPN_DESIRED_ENABLED_KEY])
            assertEquals(true, onDisk[VPN_EXPLICIT_CHOICE_KEY])
            assertFalse(store.snapshot().shouldRecoverFromSystemStart(systemAlwaysOn = true))
        }
    }

    private fun recordingPreferences(
        inMemory: MutableMap<String, Boolean>,
        onDisk: MutableMap<String, Boolean>,
        commitResults: MutableList<Boolean>
    ): SharedPreferences {
        val pending = mutableMapOf<String, Boolean>()
        val editor = Proxy.newProxyInstance(
            SharedPreferences.Editor::class.java.classLoader,
            arrayOf(SharedPreferences.Editor::class.java)
        ) { proxy, method, arguments ->
            when (method.name) {
                "putBoolean" -> {
                    pending[arguments!![0] as String] = arguments[1] as Boolean
                    proxy
                }
                "commit" -> {
                    inMemory.putAll(pending)
                    val result = commitResults.removeAt(0)
                    if (result) onDisk.putAll(pending)
                    result
                }
                "apply" -> error("Intent state must await a synchronous durable write")
                else -> error("Unexpected SharedPreferences.Editor method: ${method.name}")
            }
        } as SharedPreferences.Editor

        return Proxy.newProxyInstance(
            SharedPreferences::class.java.classLoader,
            arrayOf(SharedPreferences::class.java)
        ) { _, method, arguments ->
            when (method.name) {
                "getBoolean" -> inMemory[arguments!![0] as String] ?: arguments[1] as Boolean
                "edit" -> editor
                else -> error("Unexpected SharedPreferences method: ${method.name}")
            }
        } as SharedPreferences
    }
}
