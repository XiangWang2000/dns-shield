package io.github.xiangwang2000.dnsshield.service

import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DnsDecisionEventBufferTest {
    private class Fixture {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val batches = Channel<Unit>(Channel.UNLIMITED)
        val snapshots = Collections.synchronizedList(mutableListOf<List<DnsDecisionEvent>>())
        var scheduled = 0
        private var now = 1_000L
        val buffer = DnsDecisionEventBuffer(
            scope = scope,
            publish = { snapshots.add(it) },
            currentTimeMillis = { now++ },
            awaitBatch = { scheduled++; batches.receive() }
        )
        fun flush() { assertTrue(batches.trySend(Unit).isSuccess) }
        fun close() { scope.cancel() }
    }

    @Test
    fun backgroundRetainsNewestHundredWithoutSnapshotsOrScheduledWork() {
        val f = Fixture()
        try {
            repeat(10_000) { f.buffer.record("blocked-$it.example", DnsDecisionReason.PROTECTION_LIST) }
            assertEquals(0, f.snapshots.size)
            assertEquals(0, f.scheduled)
            f.buffer.setForeground(true)
            val snapshot = f.snapshots.single()
            assertEquals(100, snapshot.size)
            assertEquals("blocked-9999.example", snapshot.first().domain)
            assertEquals("blocked-9900.example", snapshot.last().domain)
            assertEquals((10_000L downTo 9_901L).toList(), snapshot.map { it.id })
            assertEquals(10_999L, snapshot.first().occurredAtMillis)
            assertTrue(snapshot.all { it.decision == DnsDecision.BLOCK && it.reason == DnsDecisionReason.PROTECTION_LIST })
        } finally { f.close() }
    }

    @Test
    fun foregroundBurstPublishesLastEventInOneBatchThenStopsScheduling() {
        val f = Fixture()
        try {
            f.buffer.setForeground(true)
            repeat(5_000) { f.buffer.record("blocked-$it.example", DnsDecisionReason.USER_RULE) }
            assertEquals(1, f.snapshots.size)
            assertEquals(1, f.scheduled)
            f.flush()
            assertEquals(2, f.snapshots.size)
            assertEquals("blocked-4999.example", f.snapshots.last().first().domain)
            assertEquals(1, f.scheduled)
            f.buffer.record("last.example", DnsDecisionReason.USER_RULE)
            assertEquals(2, f.scheduled)
            f.flush()
            assertEquals("last.example", f.snapshots.last().first().domain)
            assertEquals(3, f.snapshots.size)
            assertEquals(2, f.scheduled)
        } finally { f.close() }
    }

    @Test
    fun backgroundCancelsPendingBatchAndForegroundImmediatelyCatchesUp() {
        val f = Fixture()
        try {
            f.buffer.setForeground(true)
            f.buffer.record("before.example", DnsDecisionReason.USER_RULE)
            f.buffer.setForeground(false)
            repeat(200) { f.buffer.record("background-$it.example", DnsDecisionReason.USER_RULE) }
            f.flush()
            assertEquals(1, f.snapshots.size)
            assertEquals(1, f.scheduled)
            f.buffer.setForeground(true)
            assertEquals("background-199.example", f.snapshots.last().first().domain)
            assertEquals(100, f.snapshots.last().size)
            assertEquals(1, f.scheduled)
        } finally { f.close() }
    }

    @Test
    fun clearDoesNotResurrectPendingEventsOrReuseIds() {
        val f = Fixture()
        try {
            f.buffer.setForeground(true)
            f.buffer.record("old.example", DnsDecisionReason.USER_RULE)
            f.buffer.clear()
            f.flush()
            assertEquals(emptyList(), f.snapshots.last())
            f.buffer.record("new.example", DnsDecisionReason.PROTECTION_LIST)
            val latest = f.snapshots.last().single()
            assertEquals("new.example", latest.domain)
            assertEquals(2L, latest.id)
        } finally { f.close() }
    }

    @Test
    fun publishedSnapshotsAreImmutableAndStableAfterRecordAndClear() {
        val f = Fixture()
        try {
            f.buffer.record("kept.example", DnsDecisionReason.USER_RULE)
            f.buffer.setForeground(true)
            val old = f.snapshots.single()
            assertFailsWith<UnsupportedOperationException> { (old as MutableList<DnsDecisionEvent>).clear() }
            f.buffer.record("later.example", DnsDecisionReason.USER_RULE)
            f.flush()
            f.buffer.clear()
            assertEquals(listOf("kept.example"), old.map { it.domain })
            assertEquals(emptyList(), f.snapshots.last())
        } finally { f.close() }
    }

    @Test
    fun delayedCanceledFlushCannotPublishOrCancelTheReplacementBatch() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val continuations = java.util.ArrayDeque<kotlin.coroutines.Continuation<Unit>>()
        val snapshots = mutableListOf<List<DnsDecisionEvent>>()
        val buffer = DnsDecisionEventBuffer(
            scope = scope,
            publish = { snapshots.add(it) },
            awaitBatch = { kotlin.coroutines.suspendCoroutine<Unit> { continuations.addLast(it) } }
        )
        try {
            buffer.setForeground(true)
            buffer.record("old.example", DnsDecisionReason.USER_RULE)
            buffer.clear()
            buffer.record("new.example", DnsDecisionReason.USER_RULE)
            assertEquals(2, continuations.size)
            continuations.removeFirst().resumeWith(Result.success(Unit))
            assertEquals(2, snapshots.size)
            buffer.record("last.example", DnsDecisionReason.PROTECTION_LIST)
            assertEquals(1, continuations.size)
            continuations.removeFirst().resumeWith(Result.success(Unit))
            assertEquals(listOf("last.example", "new.example"), snapshots.last().map { it.domain })
            assertEquals(3, snapshots.size)
        } finally {
            scope.cancel()
            while (continuations.isNotEmpty()) continuations.removeFirst().resumeWith(Result.success(Unit))
        }
    }

    @Test
    fun concurrentRecordClearAndVisibilityChangesStayBoundedAndOrdered() {
        val f = Fixture()
        val pool = Executors.newFixedThreadPool(6)
        val start = CountDownLatch(1)
        try {
            val writers = (0..3).map { writer ->
                pool.submit {
                    assertTrue(start.await(5, TimeUnit.SECONDS))
                    repeat(1_000) { f.buffer.record("$writer-$it.example", DnsDecisionReason.USER_RULE) }
                }
            }
            val switches = pool.submit {
                assertTrue(start.await(5, TimeUnit.SECONDS))
                repeat(100) { f.buffer.setForeground(true); f.buffer.setForeground(false) }
            }
            val clears = pool.submit {
                assertTrue(start.await(5, TimeUnit.SECONDS))
                repeat(100) { f.buffer.clear() }
            }
            start.countDown()
            (writers + listOf(switches, clears)).forEach { it.get(10, TimeUnit.SECONDS) }
            f.buffer.setForeground(false)
            f.buffer.clear()
            f.buffer.record("final.example", DnsDecisionReason.PROTECTION_LIST)
            f.buffer.setForeground(true)
            assertEquals("final.example", f.snapshots.last().single().domain)
            f.snapshots.forEach { snapshot ->
                assertTrue(snapshot.size <= 100)
                assertTrue(snapshot.zipWithNext().all { (a, b) -> a.id > b.id })
            }
        } finally { pool.shutdownNow(); f.close() }
    }
}
