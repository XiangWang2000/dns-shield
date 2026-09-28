package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue

class BoundedDnsQueryAdmissionTest {
    @Test
    fun boundsUniqueKeysAndSameKeyWaitersUntilEveryRequestFinishes() {
        val admission = BoundedDnsQueryAdmission<String>(maxUniqueKeys = 2, maxWaitersPerKey = 2)
        val leaderA = assertIs<DnsQueryAdmission.Leader<String>>(admission.tryAdmit("a"))
        val waiterA1 = assertIs<DnsQueryAdmission.Waiter<String>>(admission.tryAdmit("a"))
        val waiterA2 = assertIs<DnsQueryAdmission.Waiter<String>>(admission.tryAdmit("a"))

        assertSame(leaderA.lease.result, waiterA1.lease.result)
        assertSame(leaderA.lease.result, waiterA2.lease.result)
        assertIs<DnsQueryAdmission.Rejected>(admission.tryAdmit("a"))

        val leaderB = assertIs<DnsQueryAdmission.Leader<String>>(admission.tryAdmit("b"))
        assertIs<DnsQueryAdmission.Rejected>(admission.tryAdmit("c"))
        assertEquals(BoundedDnsQueryAdmission.Snapshot(2, 4, 2), admission.snapshot())

        val expected = byteArrayOf(1, 2, 3)
        admission.completeLeader(leaderA.lease, expected)
        admission.release(leaderA.lease)
        assertTrue(waiterA1.lease.result.isCompleted)
        assertEquals(BoundedDnsQueryAdmission.Snapshot(2, 3, 2), admission.snapshot())

        admission.release(waiterA1.lease)
        admission.release(waiterA2.lease)
        assertEquals(BoundedDnsQueryAdmission.Snapshot(1, 1, 0), admission.snapshot())
        admission.completeLeader(leaderB.lease, null)
        admission.release(leaderB.lease)
        assertEquals(BoundedDnsQueryAdmission.Snapshot(0, 0, 0), admission.snapshot())
    }

    @Test
    fun loadOfUniqueAndDuplicateKeysNeverExceedsConfiguredBounds() {
        val maxUniqueKeys = 24
        val maxWaitersPerKey = 8
        val admission = BoundedDnsQueryAdmission<Int>(maxUniqueKeys, maxWaitersPerKey)
        val leaders = mutableListOf<BoundedDnsQueryAdmission.Lease<Int>>()
        var rejectedUnique = 0

        repeat(10_000) { key ->
            when (val result = admission.tryAdmit(key)) {
                is DnsQueryAdmission.Leader -> leaders += result.lease
                is DnsQueryAdmission.Waiter -> error("unique keys unexpectedly coalesced")
                DnsQueryAdmission.Rejected -> rejectedUnique++
            }
        }
        assertEquals(maxUniqueKeys, leaders.size)
        assertEquals(10_000 - maxUniqueKeys, rejectedUnique)

        val waiters = mutableListOf<BoundedDnsQueryAdmission.Lease<Int>>()
        var rejectedWaiters = 0
        leaders.forEachIndexed { index, leader ->
            repeat(1_000) {
                when (val result = admission.tryAdmit(index)) {
                    is DnsQueryAdmission.Waiter -> waiters += result.lease
                    is DnsQueryAdmission.Leader -> error("an admitted key lost its leader")
                    DnsQueryAdmission.Rejected -> rejectedWaiters++
                }
            }
        }

        assertEquals(maxUniqueKeys * maxWaitersPerKey, waiters.size)
        assertEquals(maxUniqueKeys * (1_000 - maxWaitersPerKey), rejectedWaiters)
        assertEquals(
            BoundedDnsQueryAdmission.Snapshot(
                uniqueKeys = maxUniqueKeys,
                activeRequests = maxUniqueKeys * (maxWaitersPerKey + 1),
                activeWaiters = maxUniqueKeys * maxWaitersPerKey
            ),
            admission.snapshot()
        )

        leaders.forEach { admission.completeLeader(it, null) }
        leaders.forEach(admission::release)
        waiters.forEach(admission::release)
        assertEquals(BoundedDnsQueryAdmission.Snapshot(0, 0, 0), admission.snapshot())
    }

    @Test
    fun releasingACancelledWaiterDoesNotCancelTheSharedLeaderResult() {
        val admission = BoundedDnsQueryAdmission<String>(maxUniqueKeys = 1, maxWaitersPerKey = 1)
        val leader = assertIs<DnsQueryAdmission.Leader<String>>(admission.tryAdmit("same"))
        val waiter = assertIs<DnsQueryAdmission.Waiter<String>>(admission.tryAdmit("same"))

        admission.release(waiter.lease)
        assertFalse(leader.lease.result.isCancelled)

        val response = byteArrayOf(7)
        admission.completeLeader(leader.lease, response)
        assertTrue(leader.lease.result.isCompleted)
        admission.release(leader.lease)
        assertEquals(BoundedDnsQueryAdmission.Snapshot(0, 0, 0), admission.snapshot())
    }
}
