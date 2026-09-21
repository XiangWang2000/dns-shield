package io.github.xiangwang2000.dnsshield.service

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsRequestDeadlineTest {
    @Test
    fun usesTheIngressTimeAndCeilsSubMillisecondBudget() {
        val receivedAtNanos = 10_000_000L
        val deadline = DnsRequestDeadline.fromReceivedAt(receivedAtNanos, timeoutMillis = 50)

        assertTrue(deadline.remainingMillis(receivedAtNanos) == 50L)
        assertTrue(deadline.remainingMillis(deadline.deadlineNanos - 1L) == 1L)
        assertTrue(deadline.remainingMillis(deadline.deadlineNanos) == 0L)
        assertTrue(deadline.remainingNanos(deadline.deadlineNanos - 1L) == 1L)
    }

    @Test
    fun fallsBackAfterDoHFailureWithinTheOriginalDeadline() = runBlocking {
        val deadline = DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 250)
        var fallbackStarted = false
        val expected = byteArrayOf(1, 2, 3)

        val response = DnsTransportFallback.resolve(
            deadline = deadline,
            primary = {
                delay(25)
                null
            },
            fallback = {
                fallbackStarted = true
                expected
            }
        )

        assertTrue(fallbackStarted)
        assertContentEquals(expected, response)
    }

    @Test
    fun doesNotStartFallbackAfterThePrimaryUsesTheWholeDeadline() = runBlocking {
        val deadline = DnsRequestDeadline.fromReceivedAt(System.nanoTime(), timeoutMillis = 50)
        var fallbackStarted = false
        val startedAt = System.nanoTime()

        val response = DnsTransportFallback.resolve(
            deadline = deadline,
            primary = {
                delay(500)
                null
            },
            fallback = {
                fallbackStarted = true
                byteArrayOf(1)
            }
        )

        val elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000L
        assertNull(response)
        assertFalse(fallbackStarted)
        assertTrue(elapsedMillis < 400L, "deadline returned after ${elapsedMillis}ms")
    }
}
