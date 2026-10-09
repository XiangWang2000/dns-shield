package io.github.xiangwang2000.dnsshield.service

import android.app.Application
import android.os.Build
import android.os.Debug
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.viewmodel.DnsVpnViewModel
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class BackgroundDiagnosticsInstrumentedTest {
    @Test
    fun backgroundEventsPublishOnForegroundAndClearCancelsPendingBatch() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertTrue("Run only in the isolated D08 test package", context.packageName.endsWith(".d08test"))
        assertEquals(15353, BuildConfig.DNS_UPSTREAM_PORT)
        assertEquals("This regression requires API 35", 35, Build.VERSION.SDK_INT)

        val testStore = ViewModelStore()
        val owner = object : ViewModelStoreOwner {
            override val viewModelStore = testStore
        }
        lateinit var viewModel: DnsVpnViewModel
        var publicationScope: CoroutineScope? = null
        var publicationCollector: Job? = null
        val publications = ConcurrentLinkedQueue<List<DnsDecisionEvent>>()

        try {
            DnsVpnService.setUiForeground(false)
            DnsVpnService.clearLogs()
            instrumentation.runOnMainSync {
                viewModel = ViewModelProvider(
                    owner,
                    ViewModelProvider.AndroidViewModelFactory.getInstance(
                        context.applicationContext as Application
                    )
                )[DnsVpnViewModel::class.java]
            }
            val collectorScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
            publicationScope = collectorScope
            publicationCollector = collectorScope.launch(start = CoroutineStart.UNDISPATCHED) {
                DnsVpnService.liveDecisionEventsFlow.collect { publications.add(it.toList()) }
            }

            assertTrue(DnsVpnService.liveDecisionEventsFlow.value.isEmpty())
            repeat(150) { index ->
                val reason = if (index % 2 == 0) {
                    DnsDecisionReason.USER_RULE
                } else {
                    DnsDecisionReason.PROTECTION_LIST
                }
                DnsVpnService.recordD08TestBlockedDomain("background-$index.example.test", reason)
            }
            assertTrue("Background events leaked to the service flow", DnsVpnService.liveDecisionEventsFlow.value.isEmpty())
            assertTrue("Background events leaked to the ViewModel", viewModel.uiState.value.blockedEvents.isEmpty())
            assertEquals("Background writes published a snapshot", 1, publications.size)

            DnsVpnService.setUiForeground(true)
            val foregroundEvents = DnsVpnService.liveDecisionEventsFlow.value
            assertEventWindow(foregroundEvents, firstIndex = 149, lastIndex = 50)
            val foregroundUi = withTimeout(FLOW_TIMEOUT_MILLIS) {
                viewModel.uiState.first { it.blockedEvents == foregroundEvents }
            }
            assertEquals(foregroundEvents, foregroundUi.blockedEvents)
            assertEquals(foregroundEvents, publications.last())

            val pendingDomain = "pending-before-clear.example.test"
            DnsVpnService.recordD08TestBlockedDomain(pendingDomain, DnsDecisionReason.USER_RULE)
            DnsVpnService.clearLogs()
            assertTrue(DnsVpnService.liveDecisionEventsFlow.value.isEmpty())
            assertTrue("clearLogs did not synchronously publish the empty snapshot", publications.last().isEmpty())
            val publicationsAfterClear = publications.size

            val afterClearDomain = "after-clear-${UUID.randomUUID().toString().replace("-", "")}.example.test"
            DnsVpnService.recordD08TestBlockedDomain(afterClearDomain, DnsDecisionReason.PROTECTION_LIST)
            val afterClearEvents = withTimeout(FLOW_TIMEOUT_MILLIS) {
                DnsVpnService.liveDecisionEventsFlow.first { events ->
                    events.any { it.domain == afterClearDomain }
                }
            }
            assertEquals(listOf(afterClearDomain), afterClearEvents.map { it.domain })
            val afterClearUi = withTimeout(FLOW_TIMEOUT_MILLIS) {
                viewModel.uiState.first { state ->
                    state.blockedEvents.any { it.domain == afterClearDomain }
                }
            }
            assertEquals(afterClearEvents, afterClearUi.blockedEvents)

            val afterClearPublications = publications.toList().drop(publicationsAfterClear)
            assertEquals(
                "The observer missed the after-clear snapshot",
                afterClearEvents,
                afterClearPublications.last()
            )
            assertTrue(
                "A pending batch resurrected pre-clear events",
                afterClearPublications.filter { it.isNotEmpty() }
                    .all { snapshot -> snapshot.map { it.domain } == listOf(afterClearDomain) }
            )
        } finally {
            publicationCollector?.cancel()
            publicationScope?.cancel()
            DnsVpnService.setUiForeground(false)
            DnsVpnService.clearLogs()
            instrumentation.runOnMainSync { testStore.clear() }
        }
    }

    @Test
    fun componentBenchmarksReportPairedRawMeasurements() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(context.packageName.endsWith(".d08test"))
        assertEquals(35, Build.VERSION.SDK_INT)
        val reportFile = File(context.cacheDir, BENCHMARK_REPORT_FILE)
        reportFile.writeText("", Charsets.UTF_8)
        val blockedEventSamples = pairedSamples(
            oldRun = ::measureOldDecisionEventFlow,
            currentRun = ::measureCurrentDecisionEventBuffer
        )
        printBenchmarkReport(
            component = "blocked-events",
            workloadCount = BLOCKED_EVENT_WORKLOAD,
            samples = blockedEventSamples,
            reportFile = reportFile,
            correctness = JSONObject()
                .put("capacity", EVENT_CAPACITY)
                .put("oldBackgroundStateFlowPublicationsPerSample", BLOCKED_EVENT_WORKLOAD)
                .put("currentBackgroundPublicationsPerSample", 0)
                .put("currentForegroundSnapshotCountPerSample", 1)
        )

        val outcomeTransports = List(SUCCESS_WORKLOAD) { index ->
            if (index % 2 == 0) DnsTransport.PLAINTEXT_UDP else DnsTransport.PLAINTEXT_TCP
        }
        val successLogSamples = pairedSamples(
            oldRun = { measureOldSuccessLogSink(outcomeTransports) },
            currentRun = { measureCurrentBackgroundLogPolicy(outcomeTransports) }
        )
        printBenchmarkReport(
            component = "successful-outcome-logs",
            workloadCount = SUCCESS_WORKLOAD,
            samples = successLogSamples,
            reportFile = reportFile,
            correctness = JSONObject()
                .put("oldFormatterAndSinkCallsPerSample", SUCCESS_WORKLOAD)
                .put("currentDetailBuilderCallsPerSample", 1)
                .put("currentSummaryBuilderCallsPerSample", 1)
                .put("currentSinkCallsPerSample", 2)
                .put("summaryProbeOutcomesOutsideTimedWorkload", 1)
        )
    }

    private fun assertEventWindow(events: List<DnsDecisionEvent>, firstIndex: Int, lastIndex: Int) {
        val expectedIndices = (firstIndex downTo lastIndex).toList()
        assertEquals(EVENT_CAPACITY, events.size)
        assertEquals(expectedIndices.map { "background-$it.example.test" }, events.map { it.domain })
        assertEquals(
            expectedIndices.map {
                if (it % 2 == 0) DnsDecisionReason.USER_RULE else DnsDecisionReason.PROTECTION_LIST
            },
            events.map { it.reason }
        )
        assertTrue(events.all { it.decision == DnsDecision.BLOCK })
        val ids = events.map { it.id }
        assertEquals(ids.size, ids.toSet().size)
        assertTrue(ids.zipWithNext().all { (newer, older) -> newer > older })
    }

    private data class BenchmarkMetrics(
        val wallNanos: Long,
        val threadCpuNanos: Long?,
        val processArtAllocatedBytesDelta: Long?,
        val processArtGcCountDelta: Long?
    )

    private data class PairedSample(
        val pair: Int,
        val implementation: String,
        val metrics: BenchmarkMetrics
    )

    private fun pairedSamples(
        oldRun: () -> BenchmarkMetrics,
        currentRun: () -> BenchmarkMetrics
    ): List<PairedSample> {
        oldRun()
        currentRun()
        val samples = ArrayList<PairedSample>(PAIRED_SAMPLE_COUNT * 2)
        repeat(PAIRED_SAMPLE_COUNT) { pair ->
            if (pair % 2 == 0) {
                samples += PairedSample(pair, "old-reference", oldRun())
                samples += PairedSample(pair, "current", currentRun())
            } else {
                samples += PairedSample(pair, "current", currentRun())
                samples += PairedSample(pair, "old-reference", oldRun())
            }
        }
        return samples
    }

    private fun measure(block: () -> Unit): BenchmarkMetrics {
        val allocatedBefore = processArtRuntimeStat("art.gc.bytes-allocated")
        val gcCountBefore = processArtRuntimeStat("art.gc.gc-count")
        val cpuBefore = Debug.threadCpuTimeNanos()
        val wallStartedAt = System.nanoTime()
        block()
        val wallNanos = System.nanoTime() - wallStartedAt
        val cpuAfter = Debug.threadCpuTimeNanos()
        val allocatedAfter = processArtRuntimeStat("art.gc.bytes-allocated")
        val gcCountAfter = processArtRuntimeStat("art.gc.gc-count")
        return BenchmarkMetrics(
            wallNanos = wallNanos,
            threadCpuNanos = if (cpuBefore >= 0L && cpuAfter >= 0L) cpuAfter - cpuBefore else null,
            processArtAllocatedBytesDelta = delta(allocatedBefore, allocatedAfter),
            processArtGcCountDelta = delta(gcCountBefore, gcCountAfter)
        )
    }

    private fun processArtRuntimeStat(name: String): Long? =
        runCatching { Debug.getRuntimeStat(name)?.toLongOrNull() }.getOrNull()

    private fun delta(before: Long?, after: Long?): Long? =
        if (before != null && after != null) after - before else null

    private class OldDecisionEventFlowReference {
        private val events = mutableListOf<DnsDecisionEvent>()
        private val eventId = java.util.concurrent.atomic.AtomicInteger(0)
        val state = MutableStateFlow<List<DnsDecisionEvent>>(emptyList())
        var publicationCount = 0

        fun record(index: Int) {
            val domain = "background-$index.example.test"
            val reason = if (index % 2 == 0) DnsDecisionReason.USER_RULE else DnsDecisionReason.PROTECTION_LIST
            synchronized(events) {
                events.add(0, DnsDecisionEvent(
                    eventId.incrementAndGet().toLong(), domain, DnsDecision.BLOCK, reason, System.currentTimeMillis()
                ))
                if (events.size > EVENT_CAPACITY) events.removeAt(events.lastIndex)
                state.value = events.toList()
                publicationCount++
            }
        }
    }

    private fun measureOldDecisionEventFlow(): BenchmarkMetrics {
        val reference = OldDecisionEventFlowReference()
        val metrics = measure {
            repeat(BLOCKED_EVENT_WORKLOAD) { reference.record(it) }
        }
        assertEquals(BLOCKED_EVENT_WORKLOAD, reference.publicationCount)
        assertEventWindow(reference.state.value, firstIndex = 9_999, lastIndex = 9_900)
        return metrics
    }

    private fun measureCurrentDecisionEventBuffer(): BenchmarkMetrics {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val snapshots = ArrayList<List<DnsDecisionEvent>>(1)
        var scheduledBatches = 0
        val buffer = DnsDecisionEventBuffer(
            scope = scope,
            capacity = EVENT_CAPACITY,
            publish = { snapshots.add(it) },
            awaitBatch = {
                scheduledBatches++
                error("Background event recording scheduled a batch")
            }
        )
        try {
            val metrics = measure {
                repeat(BLOCKED_EVENT_WORKLOAD) { index ->
                    buffer.record(blockedDomain(index), blockedReason(index))
                }
            }
            assertTrue(snapshots.isEmpty())
            assertEquals(0, scheduledBatches)
            buffer.setForeground(true)
            assertEquals(1, snapshots.size)
            assertEventWindow(snapshots.single(), firstIndex = 9_999, lastIndex = 9_900)
            return metrics
        } finally {
            scope.cancel()
        }
    }
    private class OldSuccessLogSinkReference {
        private val lines = ArrayList<String>(EVENT_CAPACITY)
        var formatCount = 0
        var sinkCount = 0
        val retainedLines: Int get() = lines.size

        fun record(transport: DnsTransport, resolverId: Int) {
            val timestamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
            val line = "[$timestamp] success transport=$transport resolver=$resolverId"
            formatCount++
            lines.add(0, line)
            if (lines.size > EVENT_CAPACITY) lines.removeAt(lines.lastIndex)
            sinkCount++
        }
    }

    private fun measureOldSuccessLogSink(outcomes: List<DnsTransport>): BenchmarkMetrics {
        val reference = OldSuccessLogSinkReference()
        val metrics = measure {
            outcomes.forEachIndexed { index, transport ->
                reference.record(transport, resolverId = index % 3 + 1)
            }
        }
        assertEquals(SUCCESS_WORKLOAD, reference.formatCount)
        assertEquals(SUCCESS_WORKLOAD, reference.sinkCount)
        assertEquals(EVENT_CAPACITY, reference.retainedLines)
        return metrics
    }

    private fun measureCurrentBackgroundLogPolicy(outcomes: List<DnsTransport>): BenchmarkMetrics {
        val lines = ArrayList<String>(EVENT_CAPACITY)
        var detailBuildCount = 0
        var summaryBuildCount = 0
        var sinkCount = 0
        var currentNanos = 0L
        var observedSummary: BackgroundDnsLogSummary? = null
        val policy = BackgroundDnsLogPolicy(
            intervalMillis = 60_000L,
            nanoTime = { currentNanos },
            sink = { message ->
                sinkCount++
                lines.add(0, message)
                if (lines.size > EVENT_CAPACITY) lines.removeAt(lines.lastIndex)
            }
        )
        val metrics = measure {
            outcomes.forEachIndexed { index, transport ->
                val resolverId = index % 3 + 1
                policy.logSuccessfulResolution(
                    transport = transport,
                    resolverId = resolverId,
                    isForeground = false,
                    detailMessage = {
                        detailBuildCount++
                        formatSuccessMessage(transport, resolverId)
                    },
                    summaryMessage = { summary ->
                        summaryBuildCount++
                        observedSummary = summary
                        formatSummaryMessage(summary)
                    }
                )
            }
        }

        assertEquals(1, detailBuildCount)
        assertEquals(0, summaryBuildCount)
        assertEquals(1, sinkCount)
        assertEquals(1, lines.size)

        // This unmeasured outcome crosses the coalescing interval and verifies the lazy summary path.
        currentNanos = 60_000_000_000L
        policy.logSuccessfulResolution(
            transport = DnsTransport.PLAINTEXT_TCP,
            resolverId = 42,
            isForeground = false,
            detailMessage = {
                detailBuildCount++
                formatSuccessMessage(DnsTransport.PLAINTEXT_TCP, 42)
            },
            summaryMessage = { summary ->
                summaryBuildCount++
                observedSummary = summary
                formatSummaryMessage(summary)
            }
        )
        assertEquals(1, detailBuildCount)
        assertEquals(1, summaryBuildCount)
        assertEquals(2, sinkCount)
        assertEquals(2, lines.size)
        assertEquals(
            BackgroundDnsLogSummary(
                coalescedEventCount = SUCCESS_WORKLOAD.toLong(),
                latestTransport = DnsTransport.PLAINTEXT_TCP,
                latestResolverId = 42
            ),
            observedSummary
        )
        return metrics
    }

    private fun formatSuccessMessage(transport: DnsTransport, resolverId: Int): String {
        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        return "[$timestamp] success transport=$transport resolver=$resolverId"
    }

    private fun formatSummaryMessage(summary: BackgroundDnsLogSummary): String {
        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        return "[$timestamp] summary events=${summary.coalescedEventCount} " +
            "transport=${summary.latestTransport} resolver=${summary.latestResolverId}"
    }

    private fun printBenchmarkReport(
        component: String,
        workloadCount: Int,
        samples: List<PairedSample>,
        reportFile: File,
        correctness: JSONObject
    ) {
        val sampleJson = JSONArray()
        samples.forEach { sample ->
            sampleJson.put(
                JSONObject()
                    .put("pair", sample.pair)
                    .put("implementation", sample.implementation)
                    .put("wallNanos", sample.metrics.wallNanos)
                    .put("threadCpuNanos", sample.metrics.threadCpuNanos ?: JSONObject.NULL)
                    .put(
                        "processArtAllocatedBytesDelta",
                        sample.metrics.processArtAllocatedBytesDelta ?: JSONObject.NULL
                    )
                    .put("processArtGcCountDelta", sample.metrics.processArtGcCountDelta ?: JSONObject.NULL)
            )
        }
        val report = JSONObject()
            .put("component", component)
            .put("workloadCountPerSample", workloadCount)
            .put("warmupPairs", 1)
            .put("measuredPairs", PAIRED_SAMPLE_COUNT)
            .put("pairOrder", "old/current, current/old, old/current")
            .put(
                "metricsNote",
                "threadCpuNanos is this instrumentation thread; ART allocation and GC deltas are process-wide and noisy"
            )
            .put("scope", "in-memory components only; no network, whole-app CPU, or battery measurement")
            .put("correctness", correctness)
            .put("samples", sampleJson)
        reportFile.appendText("$report\n", Charsets.UTF_8)
        println("D08_BACKGROUND_DIAGNOSTICS_BENCHMARK $report")
    }

    private companion object {
        const val EVENT_CAPACITY = 100
        const val BLOCKED_EVENT_WORKLOAD = 10_000
        const val SUCCESS_WORKLOAD = 5_000
        const val PAIRED_SAMPLE_COUNT = 3
        const val FLOW_TIMEOUT_MILLIS = 5_000L
        const val BENCHMARK_REPORT_FILE = "d08-background-diagnostics-benchmark.jsonl"

        fun blockedEvent(index: Int) = DnsDecisionEvent(
            id = index.toLong() + 1L,
            domain = blockedDomain(index),
            decision = DnsDecision.BLOCK,
            reason = blockedReason(index),
            occurredAtMillis = index.toLong() + 1L
        )

        fun blockedDomain(index: Int) = "background-$index.example.test"

        fun blockedReason(index: Int) =
            if (index % 2 == 0) DnsDecisionReason.USER_RULE else DnsDecisionReason.PROTECTION_LIST
    }
}
