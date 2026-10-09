package io.github.xiangwang2000.dnsshield.service

import java.io.ByteArrayInputStream
import java.lang.management.ManagementFactory
import java.lang.management.ThreadMXBean
import java.util.Locale
import kotlin.test.Test
import kotlinx.coroutines.runBlocking

/**
 * Measures the current response path on a fixed JVM fixture set. Structural counts are derived
 * from the call sites below and the production call chain; they are not runtime parser counters.
 * The reported timings and allocation totals are JVM component measurements, not Android results.
 */
class DnsResponseParseBenchmarkTest {
    @Test
    fun reportsCurrentResponsePathCosts() {
        scenarios().forEach(::report)
        check(benchmarkSink != 0L)
    }

    private data class Fixture(
        val name: String,
        val query: ParsedDnsQuery,
        val response: ByteArray,
        val recordCount: Int
    )

    private data class Scenario(
        val name: String,
        val bodyReads: Int,
        val validations: Int,
        val cacheCreates: Int,
        val cacheHits: Int,
        val cacheMetadataPasses: Int,
        val truncateCalls: Int,
        val truncateScanPasses: Int,
        val clientDeliveries: Int,
        val recordCount: Int,
        val runBatch: () -> Unit
    )

    private data class Sample(
        val wallNanos: Long,
        val cpuNanos: Long?,
        val allocatedBytes: Long?
    )

    private fun scenarios(): List<Scenario> {
        val fixtures = listOf(
            positiveFixture("a", type = 1, data = byteArrayOf(192.toByte(), 0, 2, 1)),
            positiveFixture("aaaa", type = 28, data = ByteArray(16) { it.toByte() }),
            negativeSoaFixture(),
            dnssecFixture(),
            largeMultiRecordFixture()
        )
        val perFixture = fixtures.flatMap { fixture ->
            listOf(validationScenario(fixture), freshResponseScenario(fixture))
        }
        return perFixture + cacheHitScenario(fixtures.first()) + coalescedScenario(fixtures.first())
    }

    private fun validationScenario(fixture: Fixture) = Scenario(
        name = "single_validation_${fixture.name}",
        bodyReads = 0,
        validations = 1,
        cacheCreates = 0,
        cacheHits = 0,
        cacheMetadataPasses = 0,
        truncateCalls = 0,
        truncateScanPasses = 0,
        clientDeliveries = 0,
        recordCount = fixture.recordCount
    ) {
        if (!DnsMessageValidator.isValidResponse(fixture.response, fixture.query)) {
            error("Fixture ${fixture.name} did not validate")
        }
        benchmarkSink = benchmarkSink + fixture.response.size.toLong()
    }

    private fun freshResponseScenario(fixture: Fixture) = Scenario(
        name = "uncached_doh_${fixture.name}",
        bodyReads = 1,
        validations = 4,
        cacheCreates = 1,
        cacheHits = 0,
        cacheMetadataPasses = 1,
        truncateCalls = 1,
        truncateScanPasses = if (requiresTruncation(fixture)) 1 else 0,
        clientDeliveries = 1,
        recordCount = fixture.recordCount
    ) {
        val response = readValidatedBody(fixture) ?: error("Fixture ${fixture.name} body was rejected")
        if (!DnsMessageValidator.isValidResponse(response, fixture.query)) {
            error("Fixture ${fixture.name} failed service validation")
        }
        val entry = DnsResponseCacheEntry.create(response, fixture.query) { 0L }
            ?: error("Fixture ${fixture.name} was not cacheable")
        val clientResponse = truncate(response, fixture)
        benchmarkSink = benchmarkSink + (entry.estimatedCacheWeightBytes + clientResponse.size).toLong()
    }

    private fun cacheHitScenario(fixture: Fixture): Scenario {
        val entry = DnsResponseCacheEntry.create(fixture.response, fixture.query) { 0L }
            ?: error("Fixture ${fixture.name} was not cacheable")
        return Scenario(
            name = "cache_hit_${fixture.name}",
            bodyReads = 0,
            validations = 1,
            cacheCreates = 0,
            cacheHits = 1,
            cacheMetadataPasses = 0,
            truncateCalls = 1,
            truncateScanPasses = if (requiresTruncation(fixture)) 1 else 0,
            clientDeliveries = 1,
            recordCount = fixture.recordCount
        ) {
            val response = entry.responseAtCurrentTime() ?: error("Prepared cache entry expired")
            val clientResponse = truncate(response, fixture)
            benchmarkSink = benchmarkSink + clientResponse.size.toLong()
        }
    }

    private fun coalescedScenario(fixture: Fixture): Scenario = Scenario(
        name = "coalesced_${WAITER_COUNT}_waiters_${fixture.name}",
        bodyReads = 1,
        validations = 3 + WAITER_COUNT + 1,
        cacheCreates = 1,
        cacheHits = 0,
        cacheMetadataPasses = 1,
        truncateCalls = WAITER_COUNT + 1,
        truncateScanPasses = if (requiresTruncation(fixture)) WAITER_COUNT + 1 else 0,
        clientDeliveries = WAITER_COUNT + 1,
        recordCount = fixture.recordCount
    ) {
        val admission = BoundedDnsQueryAdmission<Int>(maxUniqueKeys = 1, maxWaitersPerKey = WAITER_COUNT)
        val leader = admission.tryAdmit(1) as? DnsQueryAdmission.Leader<Int>
            ?: error("Expected one coalesced leader")
        val waiters = List(WAITER_COUNT) {
            admission.tryAdmit(1) as? DnsQueryAdmission.Waiter<Int> ?: error("Expected a coalesced waiter")
        }
        try {
            val response = readValidatedBody(fixture) ?: error("Fixture ${fixture.name} body was rejected")
            if (!DnsMessageValidator.isValidResponse(response, fixture.query)) {
                error("Fixture ${fixture.name} failed service validation")
            }
            val entry = DnsResponseCacheEntry.create(response, fixture.query) { 0L }
                ?: error("Fixture ${fixture.name} was not cacheable")
            admission.completeLeader(leader.lease, response)
            val waiterResponses = runBlocking { waiters.map { it.lease.result.await() } }
            val allResponses = listOf(response) + waiterResponses.map {
                it ?: error("Coalesced response was empty")
            }
            var totalBytes = entry.estimatedCacheWeightBytes.toLong()
            allResponses.forEach { sharedResponse ->
                totalBytes += truncate(sharedResponse, fixture).size
            }
            benchmarkSink = benchmarkSink + totalBytes
        } finally {
            waiters.forEach { admission.release(it.lease) }
            admission.release(leader.lease)
        }
    }

    private fun readValidatedBody(fixture: Fixture): ByteArray? =
        DnsDohResponseValidator.readValidatedBody(
            contentType = "application/dns-message",
            contentLength = fixture.response.size.toLong(),
            stream = ByteArrayInputStream(fixture.response),
            query = fixture.query
        )

    private fun truncate(response: ByteArray, fixture: Fixture): ByteArray =
        DnsMessageValidator.truncateResponseForClient(
            response,
            fixture.query,
            DnsMessageValidator.maxClientUdpResponseBytes(fixture.query)
        ) ?: error("Fixture ${fixture.name} could not be delivered")

    private fun requiresTruncation(fixture: Fixture): Boolean =
        fixture.response.size > DnsMessageValidator.maxClientUdpResponseBytes(fixture.query)

    private fun report(scenario: Scenario) {
        repeat(WARMUP_ROUNDS) { repeat(ITERATIONS_PER_SAMPLE) { scenario.runBatch() } }
        val samples = List(MEASURED_ROUNDS) { measure(scenario) }
        val medianWall = median(samples.map { it.wallNanos })
        val medianCpu = median(samples.mapNotNull { it.cpuNanos })
        val medianAllocated = median(samples.mapNotNull { it.allocatedBytes })
        println(
            "DNS_RESPONSE_PARSE_BENCHMARK runtime=jvm workload=${scenario.name} " +
                "batches_per_sample=$ITERATIONS_PER_SAMPLE client_deliveries_per_batch=${scenario.clientDeliveries} " +
                "structural_body_reads_per_batch=${scenario.bodyReads} " +
                "structural_is_valid_response_calls_per_batch=${scenario.validations} " +
                "structural_cache_creates_per_batch=${scenario.cacheCreates} " +
                "structural_cache_hits_per_batch=${scenario.cacheHits} " +
                "structural_cache_metadata_passes_per_batch=${scenario.cacheMetadataPasses} " +
                "structural_cache_metadata_rr_visits_per_batch=${scenario.cacheMetadataPasses * scenario.recordCount} " +
                "structural_truncate_calls_per_batch=${scenario.truncateCalls} " +
                "structural_truncate_rr_scan_passes_per_batch=${scenario.truncateScanPasses} " +
                "median_wall_ns_per_batch=${format(medianWall.toDouble() / ITERATIONS_PER_SAMPLE)} " +
                "median_cpu_ns_per_batch=${formatCpuOrBelowResolution(medianCpu, ITERATIONS_PER_SAMPLE)} " +
                "median_allocated_bytes_per_batch=${formatOrUnsupported(medianAllocated, ITERATIONS_PER_SAMPLE)}"
        )
    }

    private fun measure(scenario: Scenario): Sample {
        val cpuBefore = currentCpuNanos()
        val allocatedBefore = currentAllocatedBytes()
        val startedAt = System.nanoTime()
        repeat(ITERATIONS_PER_SAMPLE) { scenario.runBatch() }
        val wallNanos = System.nanoTime() - startedAt
        val cpuAfter = currentCpuNanos()
        val allocatedAfter = currentAllocatedBytes()
        return Sample(
            wallNanos = wallNanos,
            cpuNanos = if (cpuBefore != null && cpuAfter != null) cpuAfter - cpuBefore else null,
            allocatedBytes = if (allocatedBefore != null && allocatedAfter != null) {
                allocatedAfter - allocatedBefore
            } else {
                null
            }
        )
    }

    private fun currentCpuNanos(): Long? = runCatching {
        if (threadBean.isCurrentThreadCpuTimeSupported) threadBean.currentThreadCpuTime else -1L
    }.getOrNull()?.takeIf { it >= 0L }

    // ThreadMXBean accepts only a thread ID; keep the Java 11-compatible API for test runners.
    @Suppress("DEPRECATION")
    private fun currentAllocatedBytes(): Long? {
        val bean = allocationBean ?: return null
        if (!bean.isThreadAllocatedMemorySupported || !bean.isThreadAllocatedMemoryEnabled) return null
        return runCatching { bean.getThreadAllocatedBytes(Thread.currentThread().id) }
            .getOrNull()
            ?.takeIf { it >= 0L }
    }

    private fun median(values: List<Long>): Long = values.sorted()[values.size / 2]

    private fun formatCpuOrBelowResolution(value: Long?, iterations: Int): String = when {
        value == null -> "unsupported"
        value == 0L -> "below_resolution"
        else -> format(value.toDouble() / iterations)
    }

    private fun formatOrUnsupported(value: Long?, iterations: Int): String =
        value?.let { format(it.toDouble() / iterations) } ?: "unsupported"

    private fun format(value: Double): String = String.format(Locale.ROOT, "%.1f", value)

    private fun positiveFixture(name: String, type: Int, data: ByteArray): Fixture {
        val queryBytes = DnsTestMessages.query(type = type)
        val response = DnsTestMessages.responseWithRecords(
            queryBytes,
            answers = listOf(DnsTestResourceRecord(type = type, ttl = 60, data = data))
        )
        return fixture(name, queryBytes, response)
    }

    private fun negativeSoaFixture(): Fixture {
        val queryBytes = DnsTestMessages.query()
        val soaData = DnsTestMessages.encodedName("ns.example.com") +
            DnsTestMessages.encodedName("hostmaster.example.com") +
            uint32(1) + uint32(3_600) + uint32(600) + uint32(86_400) + uint32(300)
        val response = DnsTestMessages.responseWithRecords(
            queryBytes,
            authorities = listOf(DnsTestResourceRecord(type = 6, ttl = 120, data = soaData, ownerName = "example.com")),
            flags = 0x8183
        )
        return fixture("negative_soa", queryBytes, response)
    }

    private fun dnssecFixture(): Fixture {
        val queryBytes = DnsTestMessages.query()
        val signature = uint16(1) + byteArrayOf(8, 2) + uint32(3_600) + uint32(2_000_000_000) +
            uint32(1_000_000_000) + uint16(1234) + DnsTestMessages.encodedName("example.com") + byteArrayOf(1, 2, 3)
        val response = DnsTestMessages.responseWithRecords(
            queryBytes,
            answers = listOf(
                DnsTestResourceRecord(type = 1, ttl = 60, data = byteArrayOf(192.toByte(), 0, 2, 1)),
                DnsTestResourceRecord(type = 46, ttl = 60, data = signature, ownerName = "example.com")
            )
        )
        return fixture("dnssec_rrsig", queryBytes, response)
    }

    private fun largeMultiRecordFixture(): Fixture {
        val queryBytes = DnsTestMessages.query(type = 28, edns = true, udpPayloadSize = 1232)
        val response = DnsTestMessages.responseWithRecords(
            queryBytes,
            answers = List(LARGE_RECORD_COUNT) { index ->
                DnsTestResourceRecord(type = 28, ttl = 60, data = ByteArray(16) { (index + it).toByte() })
            }
        )
        return fixture("large_aaaa_multi_record", queryBytes, response)
    }

    private fun fixture(name: String, queryBytes: ByteArray, response: ByteArray): Fixture {
        val query = (DnsMessageValidator.parseQuery(queryBytes) as? DnsQueryParseResult.Valid)?.query
            ?: error("Invalid fixture query $name")
        return Fixture(name, query, response, DnsTestMessages.records(response).size)
    }

    private fun uint16(value: Int): ByteArray = byteArrayOf((value ushr 8).toByte(), value.toByte())

    private fun uint32(value: Long): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte()
    )

    private companion object {
        const val WAITER_COUNT = 4
        const val LARGE_RECORD_COUNT = 60
        const val WARMUP_ROUNDS = 2
        const val MEASURED_ROUNDS = 7
        const val ITERATIONS_PER_SAMPLE = 500

        private val threadBean: ThreadMXBean = ManagementFactory.getThreadMXBean()
        private val allocationBean = (threadBean as? com.sun.management.ThreadMXBean)?.also { bean ->
            if (bean.isThreadAllocatedMemorySupported && !bean.isThreadAllocatedMemoryEnabled) {
                runCatching { bean.setThreadAllocatedMemoryEnabled(true) }
            }
        }

        @Volatile
        var benchmarkSink = 0L
    }
}