package io.github.xiangwang2000.dnsshield.service

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DnsBoundedAdmissionDeviceLoadTest {
    @Test
    fun concurrentUniqueAndDuplicateBurstsStayWithinConfiguredHeapAndPendingBounds() {
        val maxUniqueKeys = 24
        val maxWaitersPerKey = 8
        val workerCount = 8
        val uniqueAttempts = 10_000
        val duplicateAttempts = maxUniqueKeys * 1_000
        val admission = BoundedDnsQueryAdmission<Int>(maxUniqueKeys, maxWaitersPerKey)
        val leaders = arrayOfNulls<BoundedDnsQueryAdmission.Lease<Int>>(maxUniqueKeys)
        val waiters = arrayOfNulls<BoundedDnsQueryAdmission.Lease<Int>>(maxUniqueKeys * maxWaitersPerKey)
        val leaderCount = AtomicInteger()
        val waiterCount = AtomicInteger()
        val rejectedUnique = AtomicInteger()
        val rejectedDuplicate = AtomicInteger()
        val elapsedNanos = LongArray(uniqueAttempts + duplicateAttempts)
        val sampleCount = AtomicInteger()
        val executor = Executors.newFixedThreadPool(workerCount)
        val runtime = Runtime.getRuntime()

        try {
            val warmup = CountDownLatch(workerCount)
            repeat(workerCount) {
                executor.execute { warmup.countDown() }
            }
            assertTrue(warmup.await(5, TimeUnit.SECONDS))
            System.gc()
            val heapBefore = runtime.totalMemory() - runtime.freeMemory()

            runConcurrentRange(executor, workerCount, uniqueAttempts) { attempt ->
                val startedAt = System.nanoTime()
                when (val result = admission.tryAdmit(attempt)) {
                    is DnsQueryAdmission.Leader -> leaders[leaderCount.getAndIncrement()] = result.lease
                    is DnsQueryAdmission.Waiter -> error("unique keys unexpectedly coalesced")
                    DnsQueryAdmission.Rejected -> rejectedUnique.incrementAndGet()
                }
                elapsedNanos[sampleCount.getAndIncrement()] = System.nanoTime() - startedAt
            }

            runConcurrentRange(executor, workerCount, duplicateAttempts) { attempt ->
                val startedAt = System.nanoTime()
                val key = leaders[(attempt % maxUniqueKeys)].let { checkNotNull(it).entry.key }
                when (val result = admission.tryAdmit(key)) {
                    is DnsQueryAdmission.Leader -> error("an admitted unique key lost its leader")
                    is DnsQueryAdmission.Waiter -> waiters[waiterCount.getAndIncrement()] = result.lease
                    DnsQueryAdmission.Rejected -> rejectedDuplicate.incrementAndGet()
                }
                elapsedNanos[sampleCount.getAndIncrement()] = System.nanoTime() - startedAt
            }

            System.gc()
            val heapAtCapacity = runtime.totalMemory() - runtime.freeMemory()
            val pendingAtCapacity = admission.snapshot()
            assertEquals(maxUniqueKeys, leaderCount.get())
            assertEquals(maxUniqueKeys * maxWaitersPerKey, waiterCount.get())
            assertEquals(uniqueAttempts - maxUniqueKeys, rejectedUnique.get())
            assertEquals(maxUniqueKeys * (1_000 - maxWaitersPerKey), rejectedDuplicate.get())
            assertEquals(
                BoundedDnsQueryAdmission.Snapshot(
                    uniqueKeys = maxUniqueKeys,
                    activeRequests = maxUniqueKeys * (maxWaitersPerKey + 1),
                    activeWaiters = maxUniqueKeys * maxWaitersPerKey
                ),
                pendingAtCapacity
            )

            val latencySamples = elapsedNanos.copyOf(sampleCount.get()).apply { sort() }
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val report = """
                {
                  "model": "${android.os.Build.MODEL}",
                  "android_release": "${android.os.Build.VERSION.RELEASE}",
                  "api_level": ${android.os.Build.VERSION.SDK_INT},
                  "worker_count": $workerCount,
                  "unique_attempts": $uniqueAttempts,
                  "duplicate_attempts": $duplicateAttempts,
                  "max_unique_keys": $maxUniqueKeys,
                  "max_waiters_per_key": $maxWaitersPerKey,
                  "max_pending_requests": ${pendingAtCapacity.activeRequests},
                  "retained_heap_delta_bytes": ${maxOf(0L, heapAtCapacity - heapBefore)},
                  "admission_p50_micros": ${percentileMicros(latencySamples, 0.50)},
                  "admission_p95_micros": ${percentileMicros(latencySamples, 0.95)},
                  "admission_p99_micros": ${percentileMicros(latencySamples, 0.99)}
                }
            """.trimIndent() + "\n"
            val reportFile = File(checkNotNull(context.getExternalFilesDir(null)), REPORT_FILE_NAME)
            reportFile.writeText(report, Charsets.UTF_8)
            println("DNS_SHIELD_ADMISSION_ANDROID_REPORT=${reportFile.absolutePath}")
            println(report)

            val success = ByteArray(32)
            leaders.filterNotNull().forEach { leader ->
                admission.completeLeader(leader, success)
                admission.release(leader)
            }
            waiters.filterNotNull().forEach(admission::release)
            assertEquals(BoundedDnsQueryAdmission.Snapshot(0, 0, 0), admission.snapshot())
            executor.shutdown()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        } finally {
            executor.shutdownNow()
        }
    }

    private fun runConcurrentRange(
        executor: java.util.concurrent.ExecutorService,
        workerCount: Int,
        attemptCount: Int,
        action: (Int) -> Unit
    ) {
        val completed = CountDownLatch(workerCount)
        repeat(workerCount) { worker ->
            executor.execute {
                try {
                    var attempt = worker
                    while (attempt < attemptCount) {
                        action(attempt)
                        attempt += workerCount
                    }
                } finally {
                    completed.countDown()
                }
            }
        }
        check(completed.await(30, TimeUnit.SECONDS)) { "admission load run did not finish" }
    }

    private fun percentileMicros(sortedSamples: LongArray, quantile: Double): Long {
        val index = ((sortedSamples.size - 1) * quantile).toInt().coerceIn(0, sortedSamples.lastIndex)
        return TimeUnit.NANOSECONDS.toMicros(sortedSamples[index])
    }

    private companion object {
        const val REPORT_FILE_NAME = "dns-admission-android-load.json"
    }
}
