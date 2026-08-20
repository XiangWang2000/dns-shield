package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MonotonicIntervalGateTest {
    @Test
    fun permitsFirstEventAndOneAfterEachInterval() {
        var now = 0L
        val gate = MonotonicIntervalGate(intervalMillis = 5, nanoTime = { now })

        assertTrue(gate.tryAcquire())
        assertFalse(gate.tryAcquire())

        now = 4_999_999L
        assertFalse(gate.tryAcquire())
        now = 5_000_000L
        assertTrue(gate.tryAcquire())
    }
}
