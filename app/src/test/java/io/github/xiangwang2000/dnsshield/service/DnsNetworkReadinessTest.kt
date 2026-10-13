package io.github.xiangwang2000.dnsshield.service

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DnsNetworkReadinessTest {
    private fun deadline(milliseconds: Long = 2_000L) =
        DnsRequestDeadline.fromReceivedAt(System.nanoTime(), milliseconds)

    @Test
    fun pendingWaitDoesNotPollAndWakesOnReadiness() = runBlocking {
        val readiness = DnsNetworkReadiness()
        var state = DnsNetworkReadiness.State.WAITING
        var reads = 0
        val waiting = async(start = CoroutineStart.UNDISPATCHED) {
            readiness.awaitReady(deadline()) { reads++; state }
        }
        val initialReads = reads
        delay(125)
        assertEquals(initialReads, reads, "No periodic state reads while the network is unchanged")
        assertFalse(waiting.isCompleted)
        state = DnsNetworkReadiness.State.READY
        readiness.signalChange()
        assertTrue(withTimeout(1_000) { waiting.await() })
    }

    @Test
    fun stateChangeDuringFirstReadIsNotLost() = runBlocking {
        val readiness = DnsNetworkReadiness()
        var firstRead = true
        assertTrue(withTimeout(1_000) {
            readiness.awaitReady(deadline()) {
                if (firstRead) {
                    firstRead = false
                    readiness.signalChange()
                    DnsNetworkReadiness.State.WAITING
                } else DnsNetworkReadiness.State.READY
            }
        })
    }

    @Test
    fun notificationBeforeSubscriptionUsesCurrentState() = runBlocking {
        val readiness = DnsNetworkReadiness()
        readiness.signalChange()
        assertTrue(readiness.awaitReady(deadline()) { DnsNetworkReadiness.State.READY })
    }

    @Test
    fun allAdmittedLeadersWakeAndOldGenerationsAreRejected() = runBlocking {
        val readiness = DnsNetworkReadiness()
        var generation = 1
        var pending = true
        val oldWaiters = List(24) {
            async(start = CoroutineStart.UNDISPATCHED) {
                readiness.awaitReady(deadline()) {
                    when {
                        generation != 1 -> DnsNetworkReadiness.State.STALE
                        pending -> DnsNetworkReadiness.State.WAITING
                        else -> DnsNetworkReadiness.State.READY
                    }
                }
            }
        }
        generation = 2
        readiness.signalChange()
        val newWaiter = async(start = CoroutineStart.UNDISPATCHED) {
            readiness.awaitReady(deadline()) {
                if (pending) DnsNetworkReadiness.State.WAITING else DnsNetworkReadiness.State.READY
            }
        }
        assertTrue(withTimeout(1_000) { oldWaiters.awaitAll() }.none { it })
        assertFalse(newWaiter.isCompleted)
        pending = false
        readiness.signalChange()
        assertTrue(withTimeout(1_000) { newWaiter.await() })
    }

    @Test
    fun staleResolverOrPolicyWakesWithoutWaitingForNetworkSettlement() = runBlocking {
        val readiness = DnsNetworkReadiness()
        var state = DnsNetworkReadiness.State.WAITING
        val waiting = async(start = CoroutineStart.UNDISPATCHED) {
            readiness.awaitReady(deadline()) { state }
        }
        state = DnsNetworkReadiness.State.STALE
        readiness.signalChange()
        assertFalse(withTimeout(1_000) { waiting.await() })
    }

    @Test
    fun unchangedNetworkTimesOutAtOriginalIngressDeadline() = runBlocking {
        val readiness = DnsNetworkReadiness()
        val receivedAt = System.nanoTime() - 500_000_000L
        val originalDeadline = DnsRequestDeadline.fromReceivedAt(receivedAt, 650)
        val start = System.nanoTime()
        assertFalse(withTimeout(1_000) {
            readiness.awaitReady(originalDeadline) { DnsNetworkReadiness.State.WAITING }
        })
        assertTrue((System.nanoTime() - start) / 1_000_000L < 500)
    }

    @Test
    fun stopCancellationDoesNotConsumeOtherWaitersNotification() = runBlocking {
        val readiness = DnsNetworkReadiness()
        var state = DnsNetworkReadiness.State.WAITING
        val stopped = async(start = CoroutineStart.UNDISPATCHED) {
            readiness.awaitReady(deadline()) { state }
        }
        val survivor = async(start = CoroutineStart.UNDISPATCHED) {
            readiness.awaitReady(deadline()) { state }
        }
        stopped.cancelAndJoin()
        assertTrue(stopped.isCancelled)
        state = DnsNetworkReadiness.State.READY
        readiness.signalChange()
        assertTrue(withTimeout(1_000) { survivor.await() })
    }

    @Test
    fun expiredDeadlineCannotStartEvenOnReadyNetwork() = runBlocking {
        val readiness = DnsNetworkReadiness()
        val expired = DnsRequestDeadline.fromReceivedAt(System.nanoTime() - 1_000_000_000L, 1)
        assertFalse(readiness.awaitReady(expired) { DnsNetworkReadiness.State.READY })
    }
}
