package io.github.xiangwang2000.dnsshield.viewmodel

import io.github.xiangwang2000.dnsshield.service.DnsPlaintextFallbackFence
import io.github.xiangwang2000.dnsshield.service.ResolverCommandCoordinator
import io.github.xiangwang2000.dnsshield.service.ResolverCommandRevisionClock
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class ResolverCommandResultTest {
    @Test
    fun daoFailureIsCapturedAsNotPersisted() = runBlocking {
        val failure = IllegalStateException("database failure")
        val deferred = CompletableDeferred<Boolean>().apply { completeExceptionally(failure) }

        val result = awaitResolverCommandResult(deferred, AtomicBoolean(false))
        val failed = assertIs<ResolverCommandResult.Failed>(result)

        assertEquals("database failure", failed.cause.message)
        assertFalse(failed.persisted)
    }
    @Test
    fun dispatchFailureAfterMutationIsCapturedAsPersisted() = runBlocking {
        val failure = IllegalStateException("service dispatch failure")
        val deferred = CompletableDeferred<Boolean>().apply { completeExceptionally(failure) }

        val result = awaitResolverCommandResult(deferred, AtomicBoolean(true))
        val failed = assertIs<ResolverCommandResult.Failed>(result)

        assertEquals("service dispatch failure", failed.cause.message)
        assertTrue(failed.persisted)
    }
    @Test
    fun cancellationFromDeferredStillPropagates() = runBlocking {
        val cancellation = CancellationException("waiter cancelled")
        val deferred = CompletableDeferred<Boolean>().apply { cancel(cancellation) }

        val actual = try {
            awaitResolverCommandResult(deferred, AtomicBoolean(false))
            error("Expected cancellation to propagate")
        } catch (exception: CancellationException) {
            exception
        }

        assertEquals(cancellation.message, actual.message)
    }

    @Test
    fun strictFailuresStayClosedAndAllowFailuresDoNotOpenFallback() = runBlocking {
        val runtimeAllowed = AtomicBoolean(true)
        val strictPersisted = AtomicBoolean(false)
        val strictFailure = IllegalStateException("database failure")

        try {
            persistFallbackPolicy(
                allow = false,
                applyRuntimePolicy = { allowed ->
                    runtimeAllowed.set(allowed)
                    true
                },
                onPersisted = { strictPersisted.set(true) },
                persist = { throw strictFailure },
                dispatch = { true }
            )
            error("Expected strict persistence to fail")
        } catch (exception: IllegalStateException) {
            assertEquals(strictFailure.message, exception.message)
        }
        assertFalse(runtimeAllowed.get())
        assertFalse(strictPersisted.get())

        runtimeAllowed.set(false)
        val allowPersisted = AtomicBoolean(false)
        try {
            persistFallbackPolicy(
                allow = true,
                applyRuntimePolicy = { allowed ->
                    runtimeAllowed.set(allowed)
                    true
                },
                onPersisted = { allowPersisted.set(true) },
                persist = { throw IllegalStateException("database failure") },
                dispatch = { true }
            )
            error("Expected allow persistence to fail")
        } catch (_: IllegalStateException) {
            // The failed update must leave the runtime fence as it was.
        }
        assertFalse(runtimeAllowed.get())
        assertFalse(allowPersisted.get())
    }

    @Test
    fun strictDispatchFailureStaysClosedAndAllowDispatchFailureDoesNotOpen() = runBlocking {
        val runtimeAllowed = AtomicBoolean(true)
        val strictPersisted = AtomicBoolean(false)
        try {
            persistFallbackPolicy(
                allow = false,
                applyRuntimePolicy = { allowed ->
                    runtimeAllowed.set(allowed)
                    true
                },
                onPersisted = { strictPersisted.set(true) },
                persist = { true },
                dispatch = { throw IllegalStateException("service dispatch failure") }
            )
            error("Expected strict dispatch to fail")
        } catch (_: IllegalStateException) {
            // Strict mode remains enforced even if dispatch fails after the commit.
        }
        assertFalse(runtimeAllowed.get())
        assertTrue(strictPersisted.get())

        runtimeAllowed.set(false)
        val allowPersisted = AtomicBoolean(false)
        try {
            persistFallbackPolicy(
                allow = true,
                applyRuntimePolicy = { allowed ->
                    runtimeAllowed.set(allowed)
                    true
                },
                onPersisted = { allowPersisted.set(true) },
                persist = { true },
                dispatch = { throw IllegalStateException("service dispatch failure") }
            )
            error("Expected allow dispatch to fail")
        } catch (_: IllegalStateException) {
            // Do not open plaintext until the service accepted the current update.
        }
        assertFalse(runtimeAllowed.get())
        assertTrue(allowPersisted.get())
    }

    @Test
    fun dispatchReturningFalseReportsSavedButUnsyncedAndDoesNotOpenAllow() = runBlocking {
        val runtimeAllowed = AtomicBoolean(false)
        val persisted = AtomicBoolean(false)

        val applied = persistFallbackPolicy(
            allow = true,
            applyRuntimePolicy = { allowed ->
                runtimeAllowed.set(allowed)
                true
            },
            onPersisted = { persisted.set(true) },
            persist = { true },
            dispatch = { false }
        )

        assertTrue(persisted.get())
        assertFalse(runtimeAllowed.get())
        assertEquals(ResolverCommandApplyStatus.SAVED_UNSYNCED, applied)
    }

    @Test
    fun rejectedRuntimeAllowFenceReportsSavedButUnsynced() = runBlocking {
        val persisted = AtomicBoolean(false)

        val applied = persistFallbackPolicy(
            allow = true,
            applyRuntimePolicy = { false },
            onPersisted = { persisted.set(true) },
            persist = { true },
            dispatch = { true }
        )

        assertTrue(persisted.get())
        assertEquals(ResolverCommandApplyStatus.SAVED_UNSYNCED, applied)
    }

    @Test
    fun sameFallbackPolicyRetryAfterDispatchFailureOpensTheExistingFence() = runBlocking {
        val resolverId = 9391
        val fence = DnsPlaintextFallbackFence()
        assertTrue(fence.requestPolicy(resolverId, 1, false))
        assertTrue(fence.markPersisted(resolverId, 1, false))
        assertTrue(fence.applyStoredPolicy(resolverId, 1, false))
        val persisted = AtomicBoolean(false)
        var revision = 2L
        val applyPolicy: (Boolean) -> Boolean = { allow ->
            if (allow) {
                fence.applyStoredPolicy(resolverId, revision, true)
            } else {
                fence.requestPolicy(resolverId, revision, false)
            }
        }

        try {
            assertTrue(fence.requestPolicy(resolverId, revision, true))
            persistFallbackPolicy(
                allow = true,
                applyRuntimePolicy = applyPolicy,
                onPersisted = {
                    persisted.set(true)
                    fence.markPersisted(resolverId, revision, true)
                },
                persist = { true },
                dispatch = { throw IllegalStateException("service dispatch failure") }
            )
            error("Expected dispatch to fail")
        } catch (_: IllegalStateException) {
            // The existing fence remains closed until the same policy is successfully retried.
        }
        assertTrue(persisted.get())
        assertFalse(fence.allows(resolverId))

        val retryPersisted = AtomicBoolean(false)
        revision = 3L
        assertTrue(fence.requestPolicy(resolverId, revision, true))
        val retried = persistFallbackPolicy(
            allow = true,
            applyRuntimePolicy = applyPolicy,
            onPersisted = {
                retryPersisted.set(true)
                fence.markPersisted(resolverId, revision, true)
            },
            persist = { true },
            dispatch = { true }
        )

        assertEquals(ResolverCommandApplyStatus.APPLIED, retried)
        assertTrue(retryPersisted.get())
        assertTrue(fence.allows(resolverId))
    }
    @Test
    fun failedAllowPersistenceDoesNotOpenStrictFence() = runBlocking {
        val resolverId = 9392
        val fence = DnsPlaintextFallbackFence()
        assertTrue(fence.requestPolicy(resolverId, 1, false))
        assertTrue(fence.markPersisted(resolverId, 1, false))
        assertTrue(fence.applyStoredPolicy(resolverId, 1, false))
        assertTrue(fence.requestPolicy(resolverId, 2, true))
        var persistedCallbackCalled = false

        val result = persistFallbackPolicy(
            allow = true,
            applyRuntimePolicy = { allowed ->
                if (allowed) fence.applyStoredPolicy(resolverId, 2, true)
                else fence.requestPolicy(resolverId, 2, false)
            },
            onPersisted = {
                persistedCallbackCalled = true
                fence.markPersisted(resolverId, 2, true)
            },
            persist = { false },
            dispatch = { true }
        )

        assertEquals(ResolverCommandApplyStatus.NOT_SAVED, result)
        assertFalse(persistedCallbackCalled)
        assertFalse(fence.applyStoredPolicy(resolverId, 3, true))
        assertFalse(fence.allows(resolverId))
    }

    @Test
    fun nextCommandResyncsLatestPersistedResolverAfterDispatchFailure() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val coordinator = ResolverCommandCoordinator(ResolverCommandRevisionClock(), scope)
        var activeResolverId = 1
        val dispatched = mutableListOf<Int>()

        try {
            val failed = coordinator.submit {
                activeResolverId = 2
                throw IllegalStateException("service dispatch failure")
            }
            val next = coordinator.submit {
                val active = activeResolverId
                dispatched += active
                active
            }

            val failedResult = awaitResolverCommandResult(failed.result, AtomicBoolean(true))
            val actualFailure = assertIs<ResolverCommandResult.Failed>(failedResult)
            assertEquals("service dispatch failure", actualFailure.cause.message)
            assertTrue(actualFailure.persisted)

            val nextResult = awaitResolverCommandResult(next.result, AtomicBoolean(false))
            assertEquals(2, (nextResult as ResolverCommandResult.Completed).value)
            assertEquals(listOf(2), dispatched)
        } finally {
            coordinator.closeAndJoin()
            scope.cancel()
        }
    }

}
