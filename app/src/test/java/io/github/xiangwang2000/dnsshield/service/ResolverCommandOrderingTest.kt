package io.github.xiangwang2000.dnsshield.service

import io.github.xiangwang2000.dnsshield.data.DnsServer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ResolverCommandOrderingTest {
    private class Fixture {
        val revisions = ResolverCommandRevisionClock()
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val coordinator = ResolverCommandCoordinator(revisions, scope)

        suspend fun close() {
            coordinator.closeAndJoin()
            scope.cancel()
        }
    }

    private fun server(id: Int) = DnsServer(
        id = id,
        name = "DNS $id",
        primaryIp = "192.0.2.$id",
        secondaryIp = null
    )

    @Test
    fun apiEntryOrderPreservesSelectionBeforeDifferentResolverFallbackEdit() = runBlocking {
        val fixture = Fixture()
        val coordinator = fixture.coordinator
        val servers = (1..2).associateWith(::server)
        var activeId = 2
        var fallbackEdited = false
        val applied = mutableListOf<Pair<Int, Long>>()
        val blockerStarted = CompletableDeferred<Unit>()
        val releaseBlocker = CompletableDeferred<Unit>()

        try {
            val blocker = coordinator.submit {
                blockerStarted.complete(Unit)
                releaseBlocker.await()
            }
            blockerStarted.await()

            // These represent API calls before their IO waiters are scheduled.
            val selectA = coordinator.submit { revision ->
                activeId = 1
                coordinator.dispatchIfCurrent(revision, servers[activeId]) { active, token ->
                    applied += active.id to token
                }
                true
            }
            val editFallbackB = coordinator.submitFallbackPolicy(2) { revision, applyFence ->
                applyFence { fallbackEdited = true }
                coordinator.dispatchIfCurrent(revision, servers[activeId]) { active, token ->
                    applied += active.id to token
                }
                true
            }
            val laterWaiter = async(Dispatchers.Default) { editFallbackB.result.await() }

            releaseBlocker.complete(Unit)
            blocker.result.await()
            assertTrue(selectA.result.await())
            assertTrue(laterWaiter.await())

            assertEquals(1, activeId)
            assertTrue(fallbackEdited)
            assertEquals(listOf(1 to editFallbackB.revision), applied)
        } finally {
            releaseBlocker.complete(Unit)
            fixture.close()
        }
    }

    @Test
    fun queuedAbaAppliesOnlyTheLastA() = runBlocking {
        val fixture = Fixture()
        val coordinator = fixture.coordinator
        val servers = mapOf(1 to server(1), 2 to server(2))
        var activeId = 2
        val applied = mutableListOf<Pair<Int, Long>>()
        val blockerStarted = CompletableDeferred<Unit>()
        val releaseBlocker = CompletableDeferred<Unit>()

        try {
            val blocker = coordinator.submit {
                blockerStarted.complete(Unit)
                releaseBlocker.await()
            }
            blockerStarted.await()
            val firstA = coordinator.submit { revision ->
                activeId = 1
                coordinator.dispatchIfCurrent(revision, servers[activeId]) { active, token ->
                    applied += active.id to token
                }
            }
            val middleB = coordinator.submit { revision ->
                activeId = 2
                coordinator.dispatchIfCurrent(revision, servers[activeId]) { active, token ->
                    applied += active.id to token
                }
            }
            val lastA = coordinator.submit { revision ->
                activeId = 1
                coordinator.dispatchIfCurrent(revision, servers[activeId]) { active, token ->
                    applied += active.id to token
                }
            }

            releaseBlocker.complete(Unit)
            blocker.result.await()
            firstA.result.await()
            middleB.result.await()
            lastA.result.await()

            assertEquals(1, activeId)
            assertEquals(listOf(1 to lastA.revision), applied)
        } finally {
            releaseBlocker.complete(Unit)
            fixture.close()
        }
    }

    @Test
    fun staleDeleteSnapshotUsesDatabaseActiveFallbackAndLaterPolicyEdit() = runBlocking {
        val fixture = Fixture()
        val coordinator = fixture.coordinator
        val servers = mapOf(1 to server(1), 2 to server(2))
        var activeId = 1
        var fallbackAllowed = true
        val applied = mutableListOf<Pair<Int, Long>>()
        val staleUiSnapshot = server(1).copy(isActive = false)
        val blockerStarted = CompletableDeferred<Unit>()
        val releaseBlocker = CompletableDeferred<Unit>()

        try {
            val blocker = coordinator.submit {
                blockerStarted.complete(Unit)
                releaseBlocker.await()
            }
            blockerStarted.await()
            val delete = coordinator.submit { revision ->
                // The DAO transaction checks persisted active state, not the stale UI snapshot.
                if (activeId == staleUiSnapshot.id) activeId = 2
                coordinator.dispatchIfCurrent(revision, servers[activeId]) { active, token ->
                    applied += active.id to token
                }
                true
            }
            val editFallback = coordinator.submitFallbackPolicy(2) { revision, applyFence ->
                applyFence { fallbackAllowed = false }
                fallbackAllowed = false
                coordinator.dispatchIfCurrent(revision, servers[activeId]) { active, token ->
                    applied += active.id to token
                }
                true
            }

            releaseBlocker.complete(Unit)
            blocker.result.await()
            assertTrue(delete.result.await())
            assertTrue(editFallback.result.await())

            assertEquals(2, activeId)
            assertFalse(fallbackAllowed)
            assertEquals(listOf(2 to editFallback.revision), applied)
        } finally {
            releaseBlocker.complete(Unit)
            fixture.close()
        }
    }

    @Test
    fun olderAllowCannotReopenSameResolverAfterStrictWasRequested() = runBlocking {
        val fixture = Fixture()
        val coordinator = fixture.coordinator
        val resolverId = 1
        val fence = DnsPlaintextFallbackFence()
        assertTrue(fence.requestPolicy(resolverId, 1, false))
        assertTrue(fence.markPersisted(resolverId, 1, false))
        assertTrue(fence.applyStoredPolicy(resolverId, 1, false))
        val blockerStarted = CompletableDeferred<Unit>()
        val releaseBlocker = CompletableDeferred<Unit>()

        try {
            val blocker = coordinator.submit {
                blockerStarted.complete(Unit)
                releaseBlocker.await()
            }
            blockerStarted.await()
            val allow = coordinator.submitFallbackPolicy(
                resolverId,
                onSubmitted = { revision -> fence.requestPolicy(resolverId, revision, true) }
            ) { revision, applyFence ->
                fence.markPersisted(resolverId, revision, true)
                applyFence { fence.applyStoredPolicy(resolverId, revision, true) }
            }
            val strict = coordinator.submitFallbackPolicy(
                resolverId,
                onSubmitted = { revision -> fence.requestPolicy(resolverId, revision, false) }
            ) { revision, applyFence ->
                fence.markPersisted(resolverId, revision, false)
                applyFence { fence.applyStoredPolicy(resolverId, revision, false) }
            }
            assertFalse(fence.allows(resolverId), "STRICT publishes while Room work is queued")

            releaseBlocker.complete(Unit)
            blocker.result.await()
            assertFalse(allow.result.await())
            assertTrue(strict.result.await())

            assertFalse(fence.allows(resolverId))
        } finally {
            releaseBlocker.complete(Unit)
            fixture.close()
        }
    }

    @Test
    fun fallbackRevisionCheckAndFenceEffectAreAtomic() = runBlocking {
        val fixture = Fixture()
        val coordinator = fixture.coordinator
        val resolverId = 45
        val fence = DnsPlaintextFallbackFence()
        val initialRevision = fixture.revisions.next()
        assertTrue(fence.requestPolicy(resolverId, initialRevision, false))
        assertTrue(fence.markPersisted(resolverId, initialRevision, false))
        assertTrue(fence.applyStoredPolicy(resolverId, initialRevision, false))
        val allowQueued = CompletableDeferred<Unit>()
        val releaseAllow = CompletableDeferred<Unit>()
        val allowPublished = java.util.concurrent.atomic.AtomicBoolean(false)

        try {
            val allow = coordinator.submitFallbackPolicy(
                resolverId,
                onSubmitted = { revision -> fence.requestPolicy(resolverId, revision, true) }
            ) { revision, applyFence ->
                allowQueued.complete(Unit)
                releaseAllow.await()
                fence.markPersisted(resolverId, revision, true)
                applyFence {
                    allowPublished.set(fence.applyStoredPolicy(resolverId, revision, true))
                }
            }
            allowQueued.await()

            val strict = coordinator.submitFallbackPolicy(
                resolverId,
                onSubmitted = { revision -> fence.requestPolicy(resolverId, revision, false) }
            ) { revision, applyFence ->
                fence.markPersisted(resolverId, revision, false)
                applyFence { fence.applyStoredPolicy(resolverId, revision, false) }
            }
            assertFalse(fence.allows(resolverId), "STRICT publishes immediately")

            releaseAllow.complete(Unit)
            assertFalse(allow.result.await(), "The queued older ALLOW is superseded")
            assertTrue(strict.result.await())
            assertFalse(allowPublished.get(), "The older ALLOW publication callback must not run")
            assertFalse(fence.allows(resolverId))
        } finally {
            releaseAllow.complete(Unit)
            fixture.close()
        }
    }
    @Test
    fun strictRequestRejectsPlaintextBeforeBlockedRoomWorkerIsReleased() = runBlocking {
        val fixture = Fixture()
        val fence = DnsPlaintextFallbackFence()
        val started = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        try {
            val blocker = fixture.coordinator.submit {
                started.complete(Unit)
                release.await()
            }
            started.await()
            val olderAllow = fixture.coordinator.submitFallbackPolicy(
                1, onSubmitted = { revision -> fence.requestPolicy(1, revision, true) }
            ) { revision, applyFence ->
                fence.markPersisted(1, revision, true)
                applyFence { fence.applyStoredPolicy(1, revision, true) }
            }
            val strict = fixture.coordinator.submitFallbackPolicy(
                1, onSubmitted = { revision -> fence.requestPolicy(1, revision, false) }
            ) { revision, applyFence ->
                fence.markPersisted(1, revision, false)
                applyFence { fence.applyStoredPolicy(1, revision, false) }
            }
            assertFalse(blocker.result.isCompleted)
            assertFalse(fence.allows(1))
            var sent = false
            assertFalse(fence.sendIfAllowed(1, true, { true }) { sent = true })
            assertFalse(sent)
            // A setter that passed its revision check before strict submission cannot reopen the guard.
            assertFalse(fence.requestPolicy(1, olderAllow.revision, true))
            assertFalse(fence.allows(1))
            release.complete(Unit)
            blocker.result.await()
            olderAllow.result.await()
            strict.result.await()
            assertFalse(fence.allows(1))
        } finally {
            release.complete(Unit)
            fixture.close()
        }
    }

    @Test
    fun canceledWaiterAndFailedCommandDoNotCancelOrBlockQueuedMutations() = runBlocking {
        val fixture = Fixture()
        val coordinator = fixture.coordinator
        val firstStarted = CompletableDeferred<Unit>()
        val releaseFirst = CompletableDeferred<Unit>()
        var completed = false

        try {
            val first = coordinator.submit {
                firstStarted.complete(Unit)
                releaseFirst.await()
                completed = true
                true
            }
            firstStarted.await()
            val waiter = async(Dispatchers.Default) { first.result.await() }
            waiter.cancelAndJoin()

            val failed = coordinator.submit<Int> { throw IllegalStateException("expected command failure") }
            val later = coordinator.submit { completed }
            releaseFirst.complete(Unit)

            assertTrue(first.result.await())
            assertFailsWith<IllegalStateException> { failed.result.await() }
            assertTrue(later.result.await())
            assertTrue(completed)
        } finally {
            releaseFirst.complete(Unit)
            fixture.close()
        }
    }

    @Test
    fun legacyServiceRefreshWaitsForPriorMutationAndUsesDatabaseActiveRow() = runBlocking {
        val fixture = Fixture()
        val coordinator = fixture.coordinator
        val fence = ResolverCommandRevisionFence(fixture.revisions)
        var databaseActive = server(2)
        var appliedId: Int? = null
        val blockerStarted = CompletableDeferred<Unit>()
        val releaseBlocker = CompletableDeferred<Unit>()

        try {
            val blocker = coordinator.submit {
                blockerStarted.complete(Unit)
                releaseBlocker.await()
            }
            blockerStarted.await()
            val selectA = coordinator.submit { revision ->
                databaseActive = server(1)
                coordinator.dispatchIfCurrent(revision, databaseActive) { _, _ -> }
            }
            val legacyRefresh = coordinator.submitReceived(requestedRevision = null) { }

            releaseBlocker.complete(Unit)
            blocker.result.await()
            selectA.result.await()
            legacyRefresh.result.await()
            assertTrue(
                fence.applyLatestActive(
                    ResolverUpdateCommand(requestedResolverId = -1, revision = legacyRefresh.revision),
                    readActive = { databaseActive },
                    apply = { appliedId = it.id }
                ) == true
            )

            assertEquals(1, appliedId)
            assertFalse(fixture.revisions.isCurrent(selectA.revision))
            val futureObserved = coordinator.submitReceived(50L) { }
            futureObserved.result.await()
            val next = coordinator.submit { it }
            assertEquals(51L, next.revision)
            assertEquals(51L, next.result.await())
        } finally {
            releaseBlocker.complete(Unit)
            fixture.close()
        }
    }

    @Test
    fun startupBarrierWaitsForEarlierCommandsWithoutAdvancingRevision() = runBlocking {
        val fixture = Fixture()
        val started = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        try {
            val blockedMutation = fixture.coordinator.submit {
                started.complete(Unit)
                release.await()
            }
            started.await()
            val revisionBeforeBarrier = fixture.revisions.current()
            val startupBarrier = async { fixture.coordinator.awaitPriorCommands() }

            assertFalse(startupBarrier.isCompleted)
            release.complete(Unit)
            blockedMutation.result.await()
            startupBarrier.await()

            assertEquals(revisionBeforeBarrier, fixture.revisions.current())
        } finally {
            release.complete(Unit)
            fixture.close()
        }
    }

    @Test
    fun delayedServiceReadRejectsOldPayloadAndAppliesCurrentActiveResolver() = runBlocking {
        val revisions = ResolverCommandRevisionClock()
        val fence = ResolverCommandRevisionFence(revisions)
        var databaseActive = server(1)
        var appliedId: Int? = null
        val legacyRevision = revisions.receive(null)
        val readStarted = CompletableDeferred<Unit>()
        val releaseRead = CompletableDeferred<Unit>()

        val oldA = async(Dispatchers.Default) {
            fence.applyLatestActive(
                ResolverUpdateCommand(requestedResolverId = 1, revision = legacyRevision),
                readActive = {
                    readStarted.complete(Unit)
                    releaseRead.await()
                    databaseActive
                },
                apply = { appliedId = it.id }
            )
        }
        readStarted.await()

        databaseActive = server(2)
        val newerRevision = revisions.receive(50L)
        releaseRead.complete(Unit)

        assertNull(oldA.await())
        assertEquals(
            true,
            fence.applyLatestActive(
                ResolverUpdateCommand(requestedResolverId = 1, revision = newerRevision),
                readActive = { databaseActive },
                apply = { appliedId = it.id }
            )
        )
        assertEquals(2, appliedId)
        assertEquals(51L, revisions.next())
        assertFalse(revisions.isCurrent(legacyRevision))
    }

    @Test
    fun processRuntimeKeepsRevisionOrderingAcrossViewModelRecreation() = runBlocking {
        val firstViewModel = ResolverCommandRuntime.coordinator
        val rebuiltViewModel = ResolverCommandRuntime.coordinator
        val oldRequest = firstViewModel.submit { it }
        val newRequest = rebuiltViewModel.submit { it }

        assertTrue(newRequest.revision > oldRequest.revision)
        assertFalse(ResolverCommandRuntime.revisions.isCurrent(oldRequest.revision))
        assertEquals(oldRequest.revision, oldRequest.result.await())
        assertEquals(newRequest.revision, newRequest.result.await())
    }
    @Test
    fun supersededAllowConvergesWhenSelectionReappliesSameActiveRow() = runBlocking {
        val fixture = Fixture()
        val fence = DnsPlaintextFallbackFence()
        val initialRevision = fixture.revisions.next()
        assertTrue(fence.requestPolicy(1, initialRevision, false))
        assertTrue(fence.markPersisted(1, initialRevision, false))
        assertTrue(fence.applyStoredPolicy(1, initialRevision, false))
        val storedAllow = java.util.concurrent.atomic.AtomicBoolean(false)
        val persisted = CompletableDeferred<Unit>()
        val selectionSubmitted = CompletableDeferred<Unit>()

        try {
            val allow = fixture.coordinator.submitFallbackPolicy(
                1,
                onSubmitted = { revision -> fence.requestPolicy(1, revision, true) }
            ) { revision, applyFence ->
                io.github.xiangwang2000.dnsshield.viewmodel.persistFallbackPolicy(
                    allow = true,
                    applyRuntimePolicy = { allowed ->
                        var policyApplied = false
                        val current = applyFence {
                            policyApplied = if (allowed) {
                                fence.applyStoredPolicy(1, revision, storedAllow.get())
                            } else {
                                fence.requestPolicy(1, revision, false)
                            }
                        }
                        current && policyApplied
                    },
                    onPersisted = {
                        fence.markPersisted(1, revision, true)
                        persisted.complete(Unit)
                    },
                    persist = { storedAllow.set(true); true },
                    dispatch = {
                        selectionSubmitted.await()
                        fixture.coordinator.dispatchIfCurrent(
                            revision,
                            server(1).copy(allowPlaintextFallback = storedAllow.get())
                        ) { _, _ -> }
                    }
                )
            }

            persisted.await()
            val selectA = fixture.coordinator.submit { revision ->
                val activeRow = server(1).copy(allowPlaintextFallback = storedAllow.get())
                var selected = false
                fixture.coordinator.dispatchIfCurrent(revision, activeRow) { row, appliedRevision ->
                    selected = fence.applyStoredPolicy(
                        row.id,
                        appliedRevision,
                        row.allowPlaintextFallback
                    )
                }
                selected
            }
            selectionSubmitted.complete(Unit)

            assertEquals(
                io.github.xiangwang2000.dnsshield.viewmodel.ResolverCommandApplyStatus.SAVED_UNSYNCED,
                allow.result.await()
            )
            assertTrue(selectA.result.await())
            assertTrue(storedAllow.get())
            assertTrue(fence.allows(1), "The later active-row apply must reconcile the saved ALLOW")
        } finally {
            selectionSubmitted.complete(Unit)
            fixture.close()
        }
    }

    @Test
    fun blockedResolverSendDoesNotHoldGlobalSubmissionLock() = runBlocking {
        val fixture = Fixture()
        val fence = DnsPlaintextFallbackFence()
        val sendStarted = CountDownLatch(1)
        val releaseSend = CountDownLatch(1)
        val sendFailure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val inFlightWriteCompleted = java.util.concurrent.atomic.AtomicBoolean(false)
        val sender = Thread {
            try {
                check(fence.sendIfAllowed(1, true, { true }) {
                    sendStarted.countDown()
                    check(releaseSend.await(5, TimeUnit.SECONDS))
                    inFlightWriteCompleted.set(true)
                })
            } catch (failure: Throwable) {
                sendFailure.set(failure)
            }
        }
        val allowEffectEntered = CountDownLatch(1)
        val allowPublished = CountDownLatch(1)
        val allowPolicyPublished = java.util.concurrent.atomic.AtomicBoolean(false)
        val allow = java.util.concurrent.atomic.AtomicReference<ResolverCommandSubmission<Unit>?>()
        val strictStarted = CountDownLatch(1)
        val strictReturned = CountDownLatch(1)
        val strict = java.util.concurrent.atomic.AtomicReference<ResolverCommandSubmission<Unit>?>()
        val strictSubmitter = Thread {
            strictStarted.countDown()
            strict.set(
                fixture.coordinator.submitFallbackPolicy(
                    1,
                    onSubmitted = { revision -> fence.requestPolicy(1, revision, false) }
                ) { revision, applyFence ->
                    fence.markPersisted(1, revision, false)
                    applyFence { fence.applyStoredPolicy(1, revision, false) }
                    Unit
                }
            )
            strictReturned.countDown()
        }

        try {
            sender.start()
            assertTrue(sendStarted.await(2, TimeUnit.SECONDS))
            allow.set(
                fixture.coordinator.submitFallbackPolicy(
                    1,
                    onSubmitted = { revision -> fence.requestPolicy(1, revision, true) }
                ) { revision, applyFence ->
                    check(fence.markPersisted(1, revision, true))
                    check(
                        applyFence {
                            allowEffectEntered.countDown()
                            allowPolicyPublished.set(fence.applyStoredPolicy(1, revision, true))
                            allowPublished.countDown()
                        }
                    )
                    Unit
                }
            )
            assertTrue(allowEffectEntered.await(2, TimeUnit.SECONDS))
            assertTrue(allowPublished.await(2, TimeUnit.SECONDS))
            assertTrue(allowPolicyPublished.get(), "ALLOW publication completes while the send is blocked")
            assertTrue(sender.isAlive, "The admitted send remains in flight through the policy update")

            strictSubmitter.start()
            assertTrue(strictStarted.await(2, TimeUnit.SECONDS))

            assertTrue(
                strictReturned.await(1, TimeUnit.SECONDS),
                "A blocked socket write must not retain the global resolver submission lock"
            )
            assertTrue(sender.isAlive, "STRICT submission returns while the admitted send is still blocked")
            assertFalse(fence.allows(1))
            var sentAfterStrict = false
            assertFalse(fence.sendIfAllowed(1, true, { true }) { sentAfterStrict = true })
            assertFalse(sentAfterStrict)
        } finally {
            releaseSend.countDown()
            sender.join(2_000)
            strictSubmitter.join(2_000)
            allow.get()?.let { runCatching { it.result.await() } }
            strict.get()?.let { runCatching { it.result.await() } }
            fixture.close()
        }
        assertFalse(sender.isAlive)
        assertNull(sendFailure.get())
        assertTrue(inFlightWriteCompleted.get(), "STRICT cannot retract an already admitted write")
    }
}
