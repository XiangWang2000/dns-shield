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
        var storedAllow = false
        var runtimeAllow = false
        val blockerStarted = CompletableDeferred<Unit>()
        val releaseBlocker = CompletableDeferred<Unit>()

        try {
            val blocker = coordinator.submit {
                blockerStarted.complete(Unit)
                releaseBlocker.await()
            }
            blockerStarted.await()
            val allow = coordinator.submitFallbackPolicy(resolverId) { _, applyFence ->
                val fenced = applyFence { runtimeAllow = true }
                storedAllow = true
                fenced
            }
            val strict = coordinator.submitFallbackPolicy(resolverId) { _, applyFence ->
                val fenced = applyFence { runtimeAllow = false }
                storedAllow = false
                fenced
            }

            releaseBlocker.complete(Unit)
            blocker.result.await()
            assertFalse(allow.result.await())
            assertTrue(strict.result.await())

            assertFalse(storedAllow)
            assertFalse(runtimeAllow)
        } finally {
            releaseBlocker.complete(Unit)
            fixture.close()
        }
    }

    @Test
    fun strictRequestRejectsPlaintextBeforeBlockedRoomWorkerIsReleased() = runBlocking {
        val fixture = Fixture()
        val fence = DnsPlaintextFallbackFence()
        val started = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var storedAllow = true
        try {
            val blocker = fixture.coordinator.submit {
                started.complete(Unit)
                release.await()
            }
            started.await()
            assertTrue(fence.allows(1))
            val olderAllow = fixture.coordinator.submitFallbackPolicy(
                1, onSubmitted = { fence.requestAllowed(1, true) }
            ) { _, applyFence ->
                applyFence { fence.setAllowed(1, true) }
                storedAllow = true
            }
            val strict = fixture.coordinator.submitFallbackPolicy(
                1, onSubmitted = { fence.requestAllowed(1, false) }
            ) { _, applyFence ->
                applyFence { fence.setAllowed(1, false) }
                storedAllow = false
            }
            assertFalse(blocker.result.isCompleted)
            assertTrue(storedAllow, "Room is still blocked; rejection must not depend on persistence")
            assertFalse(fence.allows(1))
            var sent = false
            assertFalse(fence.sendIfAllowed(1, true, { true }) { sent = true })
            assertFalse(sent)
            // A setter that passed its revision check before strict submission cannot reopen the guard.
            fence.setAllowed(1, true)
            assertFalse(fence.allows(1))
            release.complete(Unit)
            blocker.result.await()
            olderAllow.result.await()
            strict.result.await()
            assertFalse(storedAllow)
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
}
