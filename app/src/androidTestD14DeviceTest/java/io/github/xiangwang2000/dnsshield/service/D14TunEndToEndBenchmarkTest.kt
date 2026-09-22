package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Debug
import android.os.Process
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.D14DeviceTestApplication
import io.github.xiangwang2000.dnsshield.D14VpnConsentActivity
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.ceil
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises DNS through the real app TUN and protected upstream socket on a device. */
@RunWith(AndroidJUnit4::class)
class D14TunEndToEndBenchmarkTest {
    private val clientTimeouts = AtomicInteger()

    @Test
    fun clientDnsTraversesTunPolicyCacheCoalescingAndFakeUpstream() {
        clientTimeouts.set(0)
        assertTrue("Run only the isolated .d14test target.", BuildConfig.D14_DEVICE_TEST)

        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext.applicationContext
        assertEquals("io.github.xiangwang2000.dnsshield.d14test", context.packageName)
        ensureVpnConsent(context)

        val upstream = FakeDnsUpstream()
        val preferences = context.getSharedPreferences(DnsVpnService.D14_TEST_PREFS_NAME, Context.MODE_PRIVATE)
        val oldHost = preferences.getString(DnsVpnService.D14_TEST_UPSTREAM_HOST_KEY, null)
        val hadPort = preferences.contains(DnsVpnService.D14_TEST_UPSTREAM_PORT_KEY)
        val oldPort = preferences.getInt(DnsVpnService.D14_TEST_UPSTREAM_PORT_KEY, -1)
        val preferencesPersisted = preferences.edit()
            .putString(DnsVpnService.D14_TEST_UPSTREAM_HOST_KEY, "127.0.0.1")
            .putInt(DnsVpnService.D14_TEST_UPSTREAM_PORT_KEY, upstream.port)
            .commit()
        if (!preferencesPersisted) {
            upstream.close()
            throw AssertionError("Could not persist the loopback-only fake upstream settings.")
        }

        val runId = System.currentTimeMillis().toString(36)
        val latencySamples = LinkedHashMap<String, MutableList<Double>>()
        val scenarioResults = JSONObject()
        val processStartedNanos = D14DeviceTestApplication.processCreatedAtElapsedRealtimeNanos
        val cpuBeforeMillis = Process.getElapsedCpuTime()
        val heapBeforeBytes = usedHeapBytes()
        val pssBeforeKb = Debug.getPss()
        val gcCountBefore = runtimeStat("art.gc.gc-count")
        val gcTimeBeforeMillis = runtimeStat("art.gc.gc-time")
        val serviceStartNanos = SystemClock.elapsedRealtimeNanos()
        var vpnReadyNanos = 0L
        var diagnosticsBefore = DnsVpnService.diagnosticsFlow.value
        var testFailure: Throwable? = null
        var cleanupFailure: Throwable? = null
        var serviceStartRequested = false
        var networkSwitchAttempted = false

        fun rememberCleanupFailure(failure: Throwable) {
            val previous = cleanupFailure
            if (previous == null) cleanupFailure = failure else previous.addSuppressed(failure)
        }

        try {
            serviceStartRequested = true
            ContextCompat.startForegroundService(
                context,
                Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
            )
            waitForLifecycle(VpnLifecycleState.RUNNING, 20_000L)
            vpnReadyNanos = SystemClock.elapsedRealtimeNanos()
            waitForSelectedValidatedPhysicalNetwork(context, 5_000L)
            assertTrue("Policy assembly should be measured in the D14 target.", DnsVpnService.d14PolicyAssemblyNanos.get() > 0L)
            DnsVpnService.resetD14Diagnostics()
            val initial = DnsVpnService.d14DiagnosticsSnapshot()
            diagnosticsBefore = initial

            val cacheDomain = "d14-cache-$runId.example.invalid"
            val miss = sendQuery(cacheDomain, 0x1401)
            assertDnsAnswer(miss.response, 0x1401)
            latencySamples.getOrPut("cache_seed_miss") { mutableListOf() }.add(miss.elapsedMillis)
            assertTrue("The fake upstream must receive the real TUN query.", upstream.waitForCount(cacheDomain, 1, 2_000L))

            val cacheHit = sendQuery(cacheDomain, 0x1402)
            assertDnsAnswer(cacheHit.response, 0x1402)
            latencySamples.getOrPut("cache_hit") { mutableListOf() }.add(cacheHit.elapsedMillis)
            assertEquals("A cache hit must not reach upstream again.", 1, upstream.count(cacheDomain))
            val afterCache = waitForDiagnostics { it.cacheHits > initial.cacheHits }
            scenarioResults.put("cache_hit", JSONObject()
                .put("passed", true)
                .put("upstream_requests_for_domain", upstream.count(cacheDomain)))

            val blockedUpstreamBefore = upstream.totalRequests.get()
            val blocked = sendQuery("doubleclick.net", 0x1403)
            assertEquals("Built-in blocked domain should return NXDOMAIN.", 3, responseCode(blocked.response))
            latencySamples.getOrPut("blocked") { mutableListOf() }.add(blocked.elapsedMillis)
            val afterBlocked = waitForDiagnostics { it.blocked > initial.blocked }
            assertEquals("A blocked query must not reach upstream.", blockedUpstreamBefore, upstream.totalRequests.get())
            scenarioResults.put("blocked", JSONObject()
                .put("passed", true)
                .put("upstream_requests", 0))

            val uniqueDomains = (0 until UNIQUE_MISS_SAMPLES).map { "d14-unique-$runId-$it.example.invalid" }
            val uniqueResults = sendConcurrentQueries(uniqueDomains, 0x2000)
            uniqueResults.forEach { result ->
                assertDnsAnswer(result.response, result.transactionId)
                latencySamples.getOrPut("unique_miss") { mutableListOf() }.add(result.elapsedMillis)
            }
            uniqueDomains.forEach { domain ->
                assertTrue("Missing fake-upstream request for $domain", upstream.waitForCount(domain, 1, 2_000L))
            }
            scenarioResults.put("unique_miss", JSONObject()
                .put("passed", true)
                .put("samples", uniqueResults.size)
                .put("upstream_requests", uniqueDomains.sumOf(upstream::count)))

            val coalescedDomain = "d14-coalesced-$runId.example.invalid"
            val coalescedBefore = upstream.count(coalescedDomain)
            upstream.delayDomain = coalescedDomain
            upstream.delayMillis = COALESCED_UPSTREAM_DELAY_MS
            val coalescedResults = sendConcurrentSameDomain(COALESCED_CLIENTS, coalescedDomain, 0x3000)
            upstream.delayDomain = null
            coalescedResults.forEach { result ->
                assertDnsAnswer(result.response, result.transactionId)
                latencySamples.getOrPut("coalesced_miss") { mutableListOf() }.add(result.elapsedMillis)
            }
            assertEquals("Concurrent identical misses should share one upstream query.", coalescedBefore + 1, upstream.count(coalescedDomain))
            val afterCoalescing = waitForDiagnostics {
                it.coalesced >= initial.coalesced + COALESCED_CLIENTS - 1
            }
            scenarioResults.put("coalesced_miss", JSONObject()
                .put("passed", true)
                .put("clients", COALESCED_CLIENTS)
                .put("upstream_requests", upstream.count(coalescedDomain) - coalescedBefore)
                .put("coalesced_wait_samples", afterCoalescing.coalescedWait.sampleCount))

            val burstDomains = (0 until BURST_CLIENTS).map { "d14-burst-$runId-$it.example.invalid" }
            val burstResults = sendConcurrentQueries(burstDomains, 0x4000)
            burstResults.forEach { result ->
                assertDnsAnswer(result.response, result.transactionId)
                latencySamples.getOrPut("burst") { mutableListOf() }.add(result.elapsedMillis)
            }
            scenarioResults.put("burst", JSONObject()
                .put("passed", true)
                .put("clients", BURST_CLIENTS)
                .put("upstream_requests", burstDomains.sumOf(upstream::count)))

            val failingDomain = "d14-upstream-fail-$runId.example.invalid"
            val failedBefore = DnsVpnService.diagnosticsFlow.value.failed
            val dropsBefore = upstream.droppedRequests.get()
            upstream.droppedDomains.add(failingDomain)
            val failedQuery = sendQuery(failingDomain, 0x5001, timeoutMillis = 8_000)
            upstream.droppedDomains.remove(failingDomain)
            assertEquals("When every configured upstream attempt fails, reply SERVFAIL.", 2, responseCode(failedQuery.response))
            latencySamples.getOrPut("all_upstreams_failed") { mutableListOf() }.add(failedQuery.elapsedMillis)
            val afterFailure = waitForDiagnostics { it.failed > failedBefore }
            assertTrue("Both upstream attempts should have been dropped.", upstream.droppedRequests.get() - dropsBefore >= 2)
            scenarioResults.put("all_upstreams_failed", JSONObject()
                .put("passed", true)
                .put("upstream_attempts_dropped", upstream.droppedRequests.get() - dropsBefore)
                .put("failed_requests_delta", afterFailure.failed - failedBefore))

            val networkBefore = waitForSelectedValidatedPhysicalNetwork(context, 5_000L)
            val networkChangeCountBefore = DnsVpnService.d14NetworkChangeCount.get()
            networkSwitchAttempted = true
            println("D14_NETWORK_SWITCH_REQUIRED=Switch Wi-Fi off and back on, or hand off between Wi-Fi and cellular, within 90 seconds.")
            val networkAfter = waitForNetworkHandoff(context, networkChangeCountBefore, networkBefore, 90_000L)
            val networkCacheCountBefore = upstream.count(cacheDomain)
            val postSwitch = sendQuery(cacheDomain, 0x6001)
            assertDnsAnswer(postSwitch.response, 0x6001)
            latencySamples.getOrPut("network_switch_recovery") { mutableListOf() }.add(postSwitch.elapsedMillis)
            assertEquals(
                "Network generation changes must invalidate the DNS answer cache.",
                networkCacheCountBefore + 1,
                upstream.count(cacheDomain)
            )
            scenarioResults.put("network_switch", JSONObject()
                .put("passed", true)
                .put("observed_service_transitions", DnsVpnService.d14NetworkChangeCount.get() - networkChangeCountBefore)
                .put("selected_network_id_before", networkBefore.selectedNetworkId ?: JSONObject.NULL)
                .put("selected_network_id_after", networkAfter.selectedNetworkId ?: JSONObject.NULL)
                .put("selected_transport_mask_before", networkBefore.selectedTransportMask)
                .put("selected_transport_mask_after", networkAfter.selectedTransportMask)
                .put("cache_requeried", true))

            val udpFallbackObserved = afterFailure.fallbackAttempts > initial.fallbackAttempts
            scenarioResults.put("udp_fallback", JSONObject()
                .put("observed", udpFallbackObserved)
                .put("fallback_attempts_delta", afterFailure.fallbackAttempts - initial.fallbackAttempts)
                .put("note", "Loopback has no configured DoH endpoint; the production transport fallback reaches the protected UDP fake upstream."))
            assertTrue("The protected UDP fallback path must be exercised.", udpFallbackObserved)

            assertTrue("Cache hit was not recorded.", afterCache.cacheHits > initial.cacheHits)
            assertTrue("Blocked query was not recorded.", afterBlocked.blocked > initial.blocked)
            assertTrue("Coalesced wait samples were not recorded.", afterCoalescing.coalescedWait.sampleCount > 0)
            assertNull("Fake upstream thread failed.", upstream.failure)
        } catch (failure: Throwable) {
            if (networkSwitchAttempted && !scenarioResults.has("network_switch")) {
                scenarioResults.put("network_switch", JSONObject()
                    .put("passed", false)
                    .put("failure", "${failure::class.java.simpleName}: ${failure.message}"))
            }
            testFailure = failure
            throw failure
        } finally {
            if (serviceStartRequested) {
                val stopIntent = Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)
                var fallbackStopUsed = false
                try {
                    context.startService(stopIntent)
                    waitForLifecycle(VpnLifecycleState.STOPPED, 10_000L)
                } catch (stopFailure: Throwable) {
                    fallbackStopUsed = true
                    try {
                        context.stopService(stopIntent)
                        waitForLifecycle(VpnLifecycleState.STOPPED, 10_000L)
                    } catch (fallbackFailure: Throwable) {
                        stopFailure.addSuppressed(fallbackFailure)
                        rememberCleanupFailure(stopFailure)
                    }
                }
                val stopped = DnsVpnService.lifecycleStateFlow.value == VpnLifecycleState.STOPPED
                scenarioResults.put("service_cleanup", JSONObject()
                    .put("passed", stopped)
                    .put("fallback_stop_used", fallbackStopUsed))
                if (!stopped && cleanupFailure == null) {
                    rememberCleanupFailure(AssertionError("DNS VPN service did not reach STOPPED during test cleanup."))
                }
            }
            val serviceStopped = DnsVpnService.lifecycleStateFlow.value == VpnLifecycleState.STOPPED
            if (serviceStopped) {
                runCatching { upstream.close() }.onFailure(::rememberCleanupFailure)
                val restored = runCatching {
                    preferences.edit().apply {
                        if (oldHost == null) remove(DnsVpnService.D14_TEST_UPSTREAM_HOST_KEY)
                        else putString(DnsVpnService.D14_TEST_UPSTREAM_HOST_KEY, oldHost)
                        if (hadPort) putInt(DnsVpnService.D14_TEST_UPSTREAM_PORT_KEY, oldPort)
                        else remove(DnsVpnService.D14_TEST_UPSTREAM_PORT_KEY)
                    }.commit()
                }.getOrElse {
                    rememberCleanupFailure(it)
                    false
                }
                if (!restored) rememberCleanupFailure(IllegalStateException("Could not restore D14 test upstream preferences."))
            } else {
                rememberCleanupFailure(AssertionError("Leaving the loopback fake upstream active because its D14 VPN did not stop."))
            }
            runCatching {
                writeReport(
                    context = context,
                    runId = runId,
                    processStartedNanos = processStartedNanos,
                    serviceStartNanos = serviceStartNanos,
                    vpnReadyNanos = vpnReadyNanos,
                    cpuBeforeMillis = cpuBeforeMillis,
                    heapBeforeBytes = heapBeforeBytes,
                    pssBeforeKb = pssBeforeKb,
                    gcCountBefore = gcCountBefore,
                    gcTimeBeforeMillis = gcTimeBeforeMillis,
                    diagnosticsBefore = diagnosticsBefore,
                    upstream = upstream,
                    latencySamples = latencySamples,
                    scenarioResults = scenarioResults,
                    failure = testFailure ?: cleanupFailure
                )
            }.onFailure(::rememberCleanupFailure)
            val finalCleanupFailure = cleanupFailure
            if (finalCleanupFailure != null) {
                val originalFailure = testFailure
                if (originalFailure != null) originalFailure.addSuppressed(finalCleanupFailure)
                else throw finalCleanupFailure
            }
        }
    }

    private fun sendQuery(domain: String, transactionId: Int, timeoutMillis: Int = 7_000): QueryResult {
        val query = buildQuery(domain, transactionId)
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMillis
            val start = SystemClock.elapsedRealtimeNanos()
            socket.send(DatagramPacket(query, query.size, InetAddress.getByName(DnsVpnService.DUMMY_DNS_IP), 53))
            val buffer = ByteArray(2_048)
            val response = DatagramPacket(buffer, buffer.size)
            try {
                socket.receive(response)
            } catch (timeout: SocketTimeoutException) {
                clientTimeouts.incrementAndGet()
                throw timeout
            }
            return QueryResult(
                transactionId = transactionId,
                response = response.data.copyOfRange(response.offset, response.offset + response.length),
                elapsedMillis = (SystemClock.elapsedRealtimeNanos() - start) / 1_000_000.0
            )
        }
    }

    private fun sendConcurrentQueries(domains: List<String>, firstTransactionId: Int): List<QueryResult> =
        sendConcurrent(domains.size) { index -> sendQuery(domains[index], firstTransactionId + index) }

    private fun sendConcurrentSameDomain(count: Int, domain: String, firstTransactionId: Int): List<QueryResult> =
        sendConcurrent(count) { index -> sendQuery(domain, firstTransactionId + index) }

    private fun sendConcurrent(count: Int, query: (Int) -> QueryResult): List<QueryResult> {
        val ready = CountDownLatch(count)
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(count)
        try {
            val futures = (0 until count).map { index ->
                executor.submit(Callable {
                    ready.countDown()
                    assertTrue("Concurrent DNS clients did not start together.", start.await(5, TimeUnit.SECONDS))
                    query(index)
                })
            }
            assertTrue("Concurrent DNS clients did not become ready.", ready.await(5, TimeUnit.SECONDS))
            start.countDown()
            return futures.map { it.get(12, TimeUnit.SECONDS) }
        } finally {
            start.countDown()
            executor.shutdownNow()
        }
    }

    private fun waitForLifecycle(expected: VpnLifecycleState, timeoutMillis: Long) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            val state = DnsVpnService.lifecycleStateFlow.value
            if (state == expected) return
            if (state == VpnLifecycleState.FAILED) {
                throw AssertionError("DNS VPN service entered FAILED while waiting for $expected")
            }
            SystemClock.sleep(25L)
        }
        throw AssertionError("Timed out waiting for VPN lifecycle $expected; current=${DnsVpnService.lifecycleStateFlow.value}")
    }

    private fun ensureVpnConsent(context: Context) {
        if (VpnService.prepare(context) == null) return
        context.startActivity(
            Intent(context, D14VpnConsentActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        val deadline = SystemClock.elapsedRealtime() + VPN_CONSENT_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            if (VpnService.prepare(context) == null) return
            SystemClock.sleep(250L)
        }
        assertNull(
            "Approve the Android VPN consent prompt for the isolated .d14test package to continue.",
            VpnService.prepare(context)
        )
    }

    @Suppress("DEPRECATION")
    private fun waitForSelectedValidatedPhysicalNetwork(
        context: Context,
        timeoutMillis: Long
    ): UnderlyingNetworkSnapshot {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            val snapshot = DnsVpnService.d14UnderlyingNetworkSnapshot.get()
            if (snapshot != null && isSelectedValidatedPhysicalNetwork(connectivityManager, snapshot)) return snapshot
            SystemClock.sleep(250L)
        }
        throw AssertionError("No selected, validated physical network was available before the handoff.")
    }

    @Suppress("DEPRECATION")
    private fun waitForNetworkHandoff(
        context: Context,
        baselineChangeCount: Long,
        baseline: UnderlyingNetworkSnapshot,
        timeoutMillis: Long
    ): UnderlyingNetworkSnapshot {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            val snapshot = DnsVpnService.d14UnderlyingNetworkSnapshot.get()
            val selectedNetworkChanged = snapshot != null &&
                (snapshot.selectedNetworkId != baseline.selectedNetworkId ||
                    snapshot.selectedTransportMask != baseline.selectedTransportMask)
            val serviceTransitioned = DnsVpnService.d14NetworkChangeCount.get() > baselineChangeCount
            if (selectedNetworkChanged && serviceTransitioned &&
                isSelectedValidatedPhysicalNetwork(connectivityManager, snapshot)
            ) {
                SystemClock.sleep(NETWORK_CHANGE_DEBOUNCE_MS)
                val stableSnapshot = DnsVpnService.d14UnderlyingNetworkSnapshot.get()
                val remainsChanged = stableSnapshot != null &&
                    (stableSnapshot.selectedNetworkId != baseline.selectedNetworkId ||
                        stableSnapshot.selectedTransportMask != baseline.selectedTransportMask)
                if (remainsChanged &&
                    isSelectedValidatedPhysicalNetwork(connectivityManager, stableSnapshot)
                ) return stableSnapshot
            }
            SystemClock.sleep(250L)
        }
        throw AssertionError("The selected validated physical network did not change during the handoff.")
    }

    @Suppress("DEPRECATION")
    private fun isSelectedValidatedPhysicalNetwork(
        connectivityManager: ConnectivityManager,
        snapshot: UnderlyingNetworkSnapshot
    ): Boolean = connectivityManager.allNetworks.any { network ->
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return@any false
        if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
            !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ||
            !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        ) return@any false

        val selectedNetworkId = snapshot.selectedNetworkId
        if (selectedNetworkId != null) {
            network.networkHandle == selectedNetworkId
        } else {
            physicalTransportMask(capabilities) == snapshot.selectedTransportMask
        }
    }

    private fun physicalTransportMask(capabilities: NetworkCapabilities): Int {
        var mask = 0
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) mask = mask or 1
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) mask = mask or 2
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) mask = mask or 4
        return mask
    }

    private fun waitForDiagnostics(
        timeoutMillis: Long = 3_000L,
        predicate: (DnsDiagnosticsSnapshot) -> Boolean
    ): DnsDiagnosticsSnapshot {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        var snapshot = DnsVpnService.diagnosticsFlow.value
        while (SystemClock.elapsedRealtime() < deadline) {
            snapshot = DnsVpnService.diagnosticsFlow.value
            if (predicate(snapshot)) return snapshot
            SystemClock.sleep(25L)
        }
        throw AssertionError("Timed out waiting for DNS diagnostics: $snapshot")
    }

    private fun writeReport(
        context: Context,
        runId: String,
        processStartedNanos: Long,
        serviceStartNanos: Long,
        vpnReadyNanos: Long,
        cpuBeforeMillis: Long,
        heapBeforeBytes: Long,
        pssBeforeKb: Long,
        gcCountBefore: Long?,
        gcTimeBeforeMillis: Long?,
        diagnosticsBefore: DnsDiagnosticsSnapshot,
        upstream: FakeDnsUpstream,
        latencySamples: Map<String, List<Double>>,
        scenarioResults: JSONObject,
        failure: Throwable?
    ) {
        val nowNanos = SystemClock.elapsedRealtimeNanos()
        val snapshot = DnsVpnService.d14DiagnosticsSnapshot()
        val packetRejectionCounts = DnsVpnService.d14PacketRejectionCountsSnapshot()
        val diagnosticDeltas = diagnosticDeltasJson(diagnosticsBefore, snapshot, clientTimeouts.get())
        val samplesJson = JSONObject()
        val summariesJson = JSONObject()
        latencySamples.forEach { (scenario, samples) ->
            val values = samples.sorted()
            samplesJson.put(scenario, JSONArray(values))
            summariesJson.put(scenario, JSONObject()
                .put("sample_count", values.size)
                .put("p50_ms", percentile(values, 0.50))
                .put("p95_ms", percentile(values, 0.95))
                .put("p99_ms", percentile(values, 0.99)))
        }
        val appCreatedToVpnReadyMs = if (processStartedNanos > 0L && vpnReadyNanos >= processStartedNanos) {
            (vpnReadyNanos - processStartedNanos) / 1_000_000.0
        } else {
            JSONObject.NULL
        }
        val runDurationMillis = (nowNanos - serviceStartNanos).coerceAtLeast(0L) / 1_000_000.0
        val cpuElapsedMillis = (Process.getElapsedCpuTime() - cpuBeforeMillis).coerceAtLeast(0L)
        val cpuOneCoreUtilizationPercent = cpuElapsedMillis * 100.0 / runDurationMillis.coerceAtLeast(1.0)
        val report = JSONObject()
            .put("schema", "dns-shield-d14-device-report-v1")
            .put("run_id", runId)
            .put("captured_at_utc", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
                timeZone = TimeZone.getTimeZone("UTC")
            }.format(Date()))
            .put("application_id", BuildConfig.APPLICATION_ID)
            .put("version_name", BuildConfig.VERSION_NAME)
            .put("device", "${Build.MANUFACTURER} ${Build.MODEL}")
            .put("build_fingerprint", Build.FINGERPRINT)
            .put("android_release", Build.VERSION.RELEASE)
            .put("sdk", Build.VERSION.SDK_INT)
            .put("service_start_to_running_ms", if (vpnReadyNanos > 0L) (vpnReadyNanos - serviceStartNanos) / 1_000_000.0 else JSONObject.NULL)
            .put("application_on_create_to_vpn_running_ms", appCreatedToVpnReadyMs)
            .put("policy_assembly_ms", DnsVpnService.d14PolicyAssemblyNanos.get().takeIf { it >= 0L }?.div(1_000_000.0) ?: JSONObject.NULL)
            .put("client_latency_samples_ms", samplesJson)
            .put("client_latency_percentiles_ms", summariesJson)
            .put("scenarios", scenarioResults)
            .put("diagnostics", diagnosticsJson(snapshot))
            .put("diagnostic_deltas", diagnosticDeltas)
            .put("packet_rejection_reason_counts", JSONObject(packetRejectionCounts))
            .put("coalesced_wait", JSONObject()
                .put("sample_scope", "coalesced waiters only; not total worker/admission queue time")
                .put("sample_count", snapshot.coalescedWait.sampleCount)
                .put("p50_ms", snapshot.coalescedWait.p50Millis ?: JSONObject.NULL)
                .put("p95_ms", snapshot.coalescedWait.p95Millis ?: JSONObject.NULL)
                .put("p99_ms", snapshot.coalescedWait.p99Millis ?: JSONObject.NULL))
            .put("upstream", JSONObject()
                .put("requests", upstream.totalRequests.get())
                .put("dropped_requests", upstream.droppedRequests.get())
                .put("requests_by_domain", upstream.countsJson()))
            .put("resources", JSONObject()
                .put("heap_used_before_bytes", heapBeforeBytes)
                .put("heap_used_after_bytes", usedHeapBytes())
                .put("pss_before_kb", pssBeforeKb)
                .put("pss_after_kb", Debug.getPss())
                .put("gc_count_before", gcCountBefore ?: JSONObject.NULL)
                .put("gc_count_after", runtimeStat("art.gc.gc-count") ?: JSONObject.NULL)
                .put("gc_time_ms_before", gcTimeBeforeMillis ?: JSONObject.NULL)
                .put("gc_time_ms_after", runtimeStat("art.gc.gc-time") ?: JSONObject.NULL)
                .put("cpu_elapsed_ms", cpuElapsedMillis)
                .put("cpu_one_core_utilization_percent", cpuOneCoreUtilizationPercent))
            .put("network_switch", JSONObject()
                .put("status", if (scenarioResults.has("network_switch")) {
                    if (scenarioResults.optJSONObject("network_switch")?.optBoolean("passed") == true) "passed" else "failed"
                } else {
                    "not_run"
                })
                .put("details", scenarioResults.optJSONObject("network_switch") ?: JSONObject()))
            .put("power_ab", JSONObject()
                .put("status", "not_run")
                .put("required_duration_hours", "8-10")
                .put("reason", "Requires separate paired same-device idle and active sessions; this short harness is not a power claim."))
            .put("run_duration_ms", runDurationMillis)
            .put("failure", failure?.let { "${it::class.java.simpleName}: ${it.message}" } ?: JSONObject.NULL)

        val reportFile = java.io.File(context.filesDir, "d14-e2e-$runId.json")
        reportFile.writeText(report.toString(2) + "\n", Charsets.UTF_8)
        assertEquals(
            "Rejected diagnostics must equal the parser rejection reason total.",
            diagnosticDeltas.getLong("rejected"),
            packetRejectionCounts.values.sum()
        )
        println("DNS_SHIELD_D14_REPORT=${reportFile.absolutePath}")
    }

    private fun diagnosticsJson(snapshot: DnsDiagnosticsSnapshot) = JSONObject()
        .put("received", snapshot.received)
        .put("resolved", snapshot.resolved)
        .put("blocked", snapshot.blocked)
        .put("failed", snapshot.failed)
        .put("rejected", snapshot.rejected)
        .put("cache_hits", snapshot.cacheHits)
        .put("coalesced", snapshot.coalesced)
        .put("overloaded", snapshot.overloaded)
        .put("udp_attempts", snapshot.udpAttempts)
        .put("udp_retries", snapshot.udpRetryAttempts)
        .put("tcp_attempts", snapshot.tcpAttempts)
        .put("fallback_attempts", snapshot.fallbackAttempts)
        .put("pending", snapshot.pending)
        .put("peak_pending", snapshot.peakPending)
        .put("latency_sample_count", snapshot.latency.sampleCount)
        .put("latency_p50_ms", snapshot.latency.p50Millis ?: JSONObject.NULL)
        .put("latency_p95_ms", snapshot.latency.p95Millis ?: JSONObject.NULL)

    private fun diagnosticDeltasJson(
        before: DnsDiagnosticsSnapshot,
        after: DnsDiagnosticsSnapshot,
        clientTimeoutCount: Int
    ): JSONObject {
        val received = (after.received - before.received).coerceAtLeast(0L)
        val errors = ((after.failed - before.failed) + (after.rejected - before.rejected)).coerceAtLeast(0L)
        return JSONObject()
            .put("received", received)
            .put("resolved", (after.resolved - before.resolved).coerceAtLeast(0L))
            .put("blocked", (after.blocked - before.blocked).coerceAtLeast(0L))
            .put("failed", (after.failed - before.failed).coerceAtLeast(0L))
            .put("rejected", (after.rejected - before.rejected).coerceAtLeast(0L))
            .put("errors", errors)
            .put("error_rate_observed_in_harness", if (received == 0L) JSONObject.NULL else errors.toDouble() / received)
            .put("client_timeout_count", clientTimeoutCount)
            .put("client_timeout_rate_observed_in_harness", if (received == 0L) JSONObject.NULL else clientTimeoutCount.toDouble() / received)
            .put("cache_hits", (after.cacheHits - before.cacheHits).coerceAtLeast(0L))
            .put("coalesced", (after.coalesced - before.coalesced).coerceAtLeast(0L))
            .put("udp_attempts", (after.udpAttempts - before.udpAttempts).coerceAtLeast(0L))
            .put("udp_retries", (after.udpRetryAttempts - before.udpRetryAttempts).coerceAtLeast(0L))
            .put("fallback_attempts", (after.fallbackAttempts - before.fallbackAttempts).coerceAtLeast(0L))
    }

    private fun buildQuery(domain: String, transactionId: Int): ByteArray {
        val labels = domain.split('.')
        require(labels.all { it.isNotEmpty() && it.length <= 63 })
        val question = labels.flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray(Charsets.US_ASCII).toList()
        }.toByteArray() + byteArrayOf(0, 0, 1, 0, 1)
        val query = ByteArray(12 + question.size)
        query[0] = (transactionId ushr 8).toByte()
        query[1] = transactionId.toByte()
        query[2] = 0x01
        query[5] = 0x01
        System.arraycopy(question, 0, query, 12, question.size)
        return query
    }

    private fun assertDnsAnswer(response: ByteArray, transactionId: Int) {
        assertTrue("DNS response is too short.", response.size >= 12)
        assertEquals((transactionId ushr 8) and 0xFF, response[0].toInt() and 0xFF)
        assertEquals(transactionId and 0xFF, response[1].toInt() and 0xFF)
        assertTrue("Expected DNS QR bit.", (response[2].toInt() and 0x80) != 0)
        assertEquals("Expected NOERROR.", 0, responseCode(response))
        assertEquals("Expected one answer record.", 1, unsignedShort(response, 6))
    }

    private fun responseCode(response: ByteArray): Int {
        assertTrue("DNS response is too short.", response.size >= 4)
        return response[3].toInt() and 0x0F
    }

    private fun unsignedShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun percentile(values: List<Double>, percentile: Double): Double? {
        if (values.isEmpty()) return null
        val index = (ceil(percentile * values.size).toInt() - 1).coerceIn(values.indices)
        return values[index]
    }

    private fun usedHeapBytes(): Long {
        val runtime = Runtime.getRuntime()
        return runtime.totalMemory() - runtime.freeMemory()
    }

    private fun runtimeStat(name: String): Long? =
        runCatching { Debug.getRuntimeStat(name)?.toLongOrNull() }.getOrNull()

    private data class QueryResult(
        val transactionId: Int,
        val response: ByteArray,
        val elapsedMillis: Double
    )

    private class FakeDnsUpstream : AutoCloseable {
        private val running = AtomicBoolean(true)
        private val socket = DatagramSocket(null).apply {
            reuseAddress = true
            bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
            soTimeout = 500
        }
        val port: Int = socket.localPort
        val totalRequests = AtomicInteger()
        val droppedRequests = AtomicInteger()
        val droppedDomains = ConcurrentHashMap.newKeySet<String>()
        @Volatile var failure: Throwable? = null
        @Volatile var delayDomain: String? = null
        @Volatile var delayMillis: Long = 0L
        private val requestCounts = ConcurrentHashMap<String, AtomicInteger>()
        private val thread = Thread(::serve, "d14-fake-dns").apply {
            isDaemon = true
            start()
        }

        fun count(domain: String): Int = requestCounts[domain]?.get() ?: 0

        fun waitForCount(domain: String, expected: Int, timeoutMillis: Long): Boolean {
            val deadline = SystemClock.elapsedRealtime() + timeoutMillis
            while (SystemClock.elapsedRealtime() < deadline) {
                if (count(domain) >= expected) return true
                SystemClock.sleep(10L)
            }
            return count(domain) >= expected
        }

        fun countsJson(): JSONObject = JSONObject().apply {
            requestCounts.toSortedMap().forEach { (domain, count) -> put(domain, count.get()) }
        }

        private fun serve() {
            val buffer = ByteArray(2_048)
            while (running.get()) {
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    val query = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    val domain = questionName(query)
                    totalRequests.incrementAndGet()
                    requestCounts.computeIfAbsent(domain) { AtomicInteger() }.incrementAndGet()
                    if (droppedDomains.contains(domain)) {
                        droppedRequests.incrementAndGet()
                        continue
                    }
                    val delay = if (delayDomain == domain) delayMillis else 0L
                    if (delay > 0L) Thread.sleep(delay)
                    val response = buildAnswer(query)
                    socket.send(DatagramPacket(response, response.size, packet.address, packet.port))
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return
                } catch (exception: Exception) {
                    if (running.get()) failure = exception
                    return
                }
            }
        }

        override fun close() {
            running.set(false)
            socket.close()
            thread.interrupt()
            thread.join(1_000L)
        }

        private fun buildAnswer(query: ByteArray): ByteArray {
            require(query.size >= 17)
            val response = query.copyOf(query.size + 16)
            response[2] = 0x81.toByte()
            response[3] = 0x80.toByte()
            response[6] = 0
            response[7] = 1
            val answer = byteArrayOf(
                0xC0.toByte(), 0x0C,
                0, 1,
                0, 1,
                0, 0, 1, 44,
                0, 4,
                203.toByte(), 0, 113, 7
            )
            System.arraycopy(answer, 0, response, query.size, answer.size)
            return response
        }

        private fun questionName(query: ByteArray): String {
            if (query.size < 13) return "invalid"
            val labels = mutableListOf<String>()
            var offset = 12
            while (offset < query.size) {
                val length = query[offset++].toInt() and 0xFF
                if (length == 0) return labels.joinToString(".").lowercase(Locale.ROOT)
                if (length > 63 || offset + length > query.size) return "invalid"
                labels += String(query, offset, length, Charsets.US_ASCII)
                offset += length
            }
            return "invalid"
        }

    }

    private companion object {
        const val VPN_CONSENT_TIMEOUT_MS = 120_000L
        const val NETWORK_CHANGE_DEBOUNCE_MS = 750L
        const val UNIQUE_MISS_SAMPLES = 12
        const val COALESCED_CLIENTS = 8
        const val COALESCED_UPSTREAM_DELAY_MS = 400L
        const val BURST_CLIENTS = 12
    }
}
