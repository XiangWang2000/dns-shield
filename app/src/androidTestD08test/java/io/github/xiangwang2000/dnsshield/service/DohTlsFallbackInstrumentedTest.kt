package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.SystemClock
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.MainActivity
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.DnsResolverMode
import io.github.xiangwang2000.dnsshield.data.DnsServer
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DohTlsFallbackInstrumentedTest {
    @Test
    fun strictModeReturnsServFailWithoutUdpAfterInvalidTlsCertificate() = runBlocking {
        runTlsFailureScenario(allowPlaintextFallback = false)
    }

    @Test
    fun allowedFallbackUsesUdpAfterTheSameInvalidTlsCertificate() = runBlocking {
        runTlsFailureScenario(allowPlaintextFallback = true)
    }

    @Test
    fun allowedFallbackUsesUdpAfterSlowDohHandshake() = runBlocking {
        runTlsFailureScenario(allowPlaintextFallback = true, handshakeDelayMillis = 4_000)
    }

    @Test
    fun strictModeDoesNotUseUdpAfterSlowDohHandshake() = runBlocking {
        runTlsFailureScenario(allowPlaintextFallback = false, handshakeDelayMillis = 4_000)
    }

    @Test
    fun optInStrictDohStartupFirstBatchBenchmark() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(
            "Pass d08StartupBench=true to run the online startup benchmark",
            arguments.getString("d08StartupBench") == "true"
        )

        val resolver = (arguments.getString("d08StartupResolver") ?: "google").lowercase()
        val (primaryIp, secondaryIp) = when (resolver) {
            "google" -> "8.8.8.8" to "8.8.4.4"
            "adguard" -> "94.140.14.14" to "94.140.15.15"
            else -> throw AssertionError("Unsupported d08StartupResolver=$resolver; use google or adguard")
        }
        val context = instrumentation.targetContext
        assertTrue("This benchmark must run in the isolated .d08test app", context.packageName.endsWith(".d08test"))


        val dao = AppDatabase.getDatabase(context).dnsDao()
        val originalServers = dao.getDnsServersList()
        val dnsServer = originalServers.single {
            !it.isCustom && it.primaryIp == primaryIp && it.secondaryIp == secondaryIp
        }
        val domains = listOf(
            "example.com",
            "example.org",
            "iana.org",
            "ietf.org",
            "wikipedia.org",
            "mozilla.org",
            "kernel.org",
            "python.org"
        )

        try {
            stopVpnIfRunning(context)
            ensureVpnConsent(context)
            assertEquals(1, dao.updatePlaintextFallback(dnsServer.id, false))
            assertTrue(dao.setActiveDnsServer(dnsServer.id))
            DnsVpnService.setD08TestPlaintextFallbackPolicy(dnsServer.id, false)
            DnsVpnService.setUiForeground(true)

            DnsVpnService.setD08StartupBenchmarkIsolation(true)
            val serviceStartElapsed = SystemClock.elapsedRealtime()
            val serviceStartEpochMillis = System.currentTimeMillis()
            startVpn(context)
            val runningElapsed = SystemClock.elapsedRealtime()
            val runningEpochMillis = System.currentTimeMillis()
            val vpnNetwork = awaitActiveVpnNetwork(context)
            val baseline = DnsVpnService.diagnosticsFlow.value
            val batchStartElapsed = SystemClock.elapsedRealtime()
            val batchStartEpochMillis = System.currentTimeMillis()
            logStartupBenchmark(
                "D08_STARTUP_BENCH_RUNNING resolver=$resolver primary_ip=$primaryIp secondary_ip=$secondaryIp " +
                    "pid=${android.os.Process.myPid()} service_start_epoch_ms=$serviceStartEpochMillis " +
                    "running_epoch_ms=$runningEpochMillis batch_start_epoch_ms=$batchStartEpochMillis " +
                    "service_start_ms=${runningElapsed - serviceStartElapsed} " +
                    "first_batch=true strict=true queries=${domains.size}"
            )

            val firstTransactionId = System.nanoTime().toInt() and 0xffff
            val results = coroutineScope {
                domains.mapIndexed { index, domain ->
                    async(Dispatchers.IO) {
                        val transactionId = (firstTransactionId + index) and 0xffff
                        val queryStart = SystemClock.elapsedRealtime()
                        val response = sendQueryThroughTunOnce(buildDnsQuery(domain, transactionId), vpnNetwork)
                        StartupDnsQueryResult(
                            domain = domain,
                            transactionId = transactionId,
                            clientMillis = SystemClock.elapsedRealtime() - queryStart,
                            response = response
                        )
                    }
                }.awaitAll()
            }

            results.forEach { result ->
                val responseCode = result.response?.getOrNull(3)?.toInt()?.and(0x0f)
                logStartupBenchmark(
                    "D08_STARTUP_BENCH_QUERY domain=${result.domain} id=${result.transactionId} " +
                        "client_ms=${result.clientMillis} rcode=${responseCode ?: "timeout"}"
                )
            }
            results.forEach { result ->
                val response = requireNotNull(result.response) { "Timed out querying ${result.domain}" }
                assertDnsTransaction(response, result.transactionId)
                assertDnsResponseCode(response, 0)
                assertTrue("${result.domain} returned no A answers", dnsAnswerCount(response) > 0)
            }

            val diagnostics = withTimeout(SERVICE_TIMEOUT_MILLIS) {
                DnsVpnService.diagnosticsFlow.first { it.terminalCount >= baseline.terminalCount + domains.size }
            }
            val dohCalls = diagnostics.dohCallsQueued - baseline.dohCallsQueued
            val udpAttempts = diagnostics.udpAttempts - baseline.udpAttempts
            val tcpAttempts = diagnostics.tcpAttempts - baseline.tcpAttempts
            assertEquals(domains.size.toLong(), dohCalls)
            assertEquals(0L, udpAttempts)
            assertEquals(0L, tcpAttempts)
            assertEquals(0L, diagnostics.fallbackAttempts - baseline.fallbackAttempts)
            logStartupBenchmark(
                "D08_STARTUP_BENCH_DONE resolver=$resolver pid=${android.os.Process.myPid()} " +
                    "finish_epoch_ms=${System.currentTimeMillis()} elapsed_ms=${SystemClock.elapsedRealtime() - batchStartElapsed} " +
                    "doh_calls=$dohCalls udp_attempts=$udpAttempts tcp_attempts=$tcpAttempts"
            )
        } finally {
            try {
                stopVpnIfRunning(context)
            } finally {
                DnsVpnService.setD08StartupBenchmarkIsolation(false)
                DnsVpnService.setUiForeground(false)
                originalServers.forEach { dao.insertDnsServer(it) }
            }
        }
    }

    @Test
    fun optInSystemDnsProviderUsesValidatedUnderlayThroughTun() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(
            "Pass d08SystemDnsTun=true to run the real System DNS regression",
            arguments.getString("d08SystemDnsTun") == "true"
        )
        assumeTrue("System DNS requires Android 10+", Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)

        val context = instrumentation.targetContext
        assertTrue("This regression must run in the isolated .d08test app", context.packageName.endsWith(".d08test"))

        val dao = AppDatabase.getDatabase(context).dnsDao()
        val originalActive = requireNotNull(dao.getActiveDnsServer())
        val systemDns = dao.getDnsServersList().single {
            it.resolverMode == DnsResolverMode.SYSTEM && !it.isCustom
        }
        assertEquals("系統 DNS", systemDns.name)

        try {
            stopVpnIfRunning(context)
            ensureVpnConsent(context)
            val underlay = awaitActivePhysicalNetwork(context)
            assertTrue("The physical underlay must be validated", underlay.isValidated)
            assertTrue("Could not select the System DNS Room preset", dao.setActiveDnsServer(systemDns.id))
            DnsVpnService.setD08StartupBenchmarkIsolation(true)
            startVpn(context)
            val vpnNetwork = awaitActiveVpnNetwork(context)
            withTimeout(SERVICE_TIMEOUT_MILLIS) {
                DnsVpnService.underlyingNetworkConnectivityFlow.first {
                    it == UnderlyingNetworkConnectivity.ONLINE
                }
            }

            val baseline = DnsVpnService.d14DiagnosticsSnapshot()
            val firstTransactionId = System.nanoTime().toInt() and 0xffff
            val blockedTransactionId = firstTransactionId
            val aTransactionId = (firstTransactionId + 1) and 0xffff
            val aaaaTransactionId = (firstTransactionId + 2) and 0xffff
            val repeatedTransactionId = (firstTransactionId + 3) and 0xffff

            val blockedResponse = requireNotNull(
                sendQueryThroughTunOnce(buildDnsQuery("doubleclick.net", blockedTransactionId), vpnNetwork)
            ) { "Timed out querying the built-in blocked domain" }
            assertDnsTransaction(blockedResponse, blockedTransactionId)
            assertDnsResponseCode(blockedResponse, 3)
            assertEquals("NXDOMAIN must not contain answers", 0, dnsAnswerCount(blockedResponse))
            val afterBlocked = awaitD14TerminalCount(baseline.terminalCount + 1)
            assertEquals(0L, afterBlocked.systemAttempts - baseline.systemAttempts)
            assertEquals(0L, afterBlocked.dohCallsQueued - baseline.dohCallsQueued)
            assertEquals(0L, afterBlocked.udpAttempts - baseline.udpAttempts)

            val aResponse = requireNotNull(
                sendQueryThroughTunOnce(buildDnsQuery("example.com", aTransactionId, queryType = 1), vpnNetwork)
            ) { "Timed out querying example.com A" }
            assertDnsTransaction(aResponse, aTransactionId)
            assertDnsResponseCode(aResponse, 0)
            assertTrue("example.com A returned no answers", dnsAnswerCount(aResponse) > 0)
            val afterA = awaitD14TerminalCount(baseline.terminalCount + 2)
            assertEquals(1L, afterA.systemAttempts - baseline.systemAttempts)

            val aaaaResponse = requireNotNull(
                sendQueryThroughTunOnce(buildDnsQuery("example.com", aaaaTransactionId, queryType = 28), vpnNetwork)
            ) { "Timed out querying example.com AAAA" }
            assertDnsTransaction(aaaaResponse, aaaaTransactionId)
            assertDnsResponseCode(aaaaResponse, 0)
            assertTrue("example.com AAAA returned no answers", dnsAnswerCount(aaaaResponse) > 0)
            val afterAaaa = awaitD14TerminalCount(baseline.terminalCount + 3)
            assertEquals(2L, afterAaaa.systemAttempts - baseline.systemAttempts)

            val repeatedAResponse = requireNotNull(
                sendQueryThroughTunOnce(buildDnsQuery("example.com", repeatedTransactionId, queryType = 1), vpnNetwork)
            ) { "Timed out repeating example.com A" }
            assertDnsTransaction(repeatedAResponse, repeatedTransactionId)
            assertDnsResponseCode(repeatedAResponse, 0)
            assertTrue("Repeated example.com A returned no answers", dnsAnswerCount(repeatedAResponse) > 0)
            val afterRepeatedA = awaitD14TerminalCount(baseline.terminalCount + 4)
            assertEquals(afterAaaa.systemAttempts, afterRepeatedA.systemAttempts)
            assertEquals(afterAaaa.cacheHits + 1, afterRepeatedA.cacheHits)
            assertEquals(0L, afterRepeatedA.dohCallsQueued - baseline.dohCallsQueued)
            assertEquals(0L, afterRepeatedA.udpAttempts - baseline.udpAttempts)
        } finally {
            try {
                stopVpnIfRunning(context)
            } finally {
                DnsVpnService.setD08StartupBenchmarkIsolation(false)
                assertTrue("Could not restore the original active DNS provider", dao.setActiveDnsServer(originalActive.id))
            }
        }
    }

    @Test
    fun strictIpv6NamedBootstrapRejectsInvalidTlsWithoutPlaintext() = runBlocking {
        runTlsFailureScenario(allowPlaintextFallback = false, ipv6 = true, namedEndpoint = true)
    }

    @Test
    fun allowedIpv6FallbackUsesIpv6UdpAfterInvalidTls() = runBlocking {
        runTlsFailureScenario(allowPlaintextFallback = true, ipv6 = true)
    }

    @Test
    fun strictModeSurvivesExternalNetworkHandoff() = runBlocking {
        val direction = InstrumentationRegistry.getArguments().getString("handoff_direction")
        assumeTrue("Pass handoff_direction=wifi-to-cellular or cellular-to-wifi", direction != null)
        assertTrue(
            "Pass handoff_direction=wifi-to-cellular or cellular-to-wifi",
            direction == "wifi-to-cellular" || direction == "cellular-to-wifi"
        )
        runStrictHandoffScenario(requireNotNull(direction))
    }

    private suspend fun runStrictHandoffScenario(direction: String) = coroutineScope {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertTrue("This suite must run in the isolated .d08test app", context.packageName.endsWith(".d08test"))


        val sourceTransport = if (direction == "wifi-to-cellular") "wifi" else "cellular"
        val targetTransport = if (direction == "wifi-to-cellular") "cellular" else "wifi"
        val dao = AppDatabase.getDatabase(context).dnsDao()
        val originalServers = dao.getDnsServersList()
        val domain = "d08-handoff-${UUID.randomUUID().toString().replace("-", "")}.example.test"
        val tlsServer = RejectingTlsServer(
            instrumentation.context,
            handshakeDelayMillis = 2_000L,
            expectedConnections = 2
        )
        val udpServer = FakeUdpDnsServer(domain)
        val resolverName = "D08 handoff TLS ${UUID.randomUUID()}"
        var resolverId: Int? = null

        try {
            stopVpnIfRunning(context)
            ensureVpnConsent(context)
            val physicalDefaultBeforeVpn = awaitActivePhysicalNetwork(context)
            assertEquals("The active physical network is not the requested handoff source", sourceTransport, physicalDefaultBeforeVpn.transport)
            DnsVpnService.setUiForeground(true)

            dao.insertDnsServer(
                DnsServer(
                    name = resolverName,
                    primaryIp = RESOLVER_IP,
                    secondaryIp = null,
                    isCustom = true,
                    isActive = false,
                    allowPlaintextFallback = false,
                    primaryDohUrl = "https://$RESOLVER_IP:${tlsServer.port}/dns-query"
                )
            )
            resolverId = dao.getDnsServersList().first { it.name == resolverName }.id
            assertTrue(dao.setActiveDnsServer(requireNotNull(resolverId)))

            startVpn(context)
            awaitActiveVpnNetwork(context)
            delay(1_000)
            val baselineFenceLogs = networkFenceLogCount()

            val inflightId = System.nanoTime().toInt() and 0xffff
            val inflightQuery = async(Dispatchers.IO) {
                sendQueryThroughTunOnce(buildDnsQuery(domain, inflightId))
            }
            tlsServer.assertClientConnected()
            assertFalse("The DoH request finished before the handoff marker", inflightQuery.isCompleted)
            val initialNetworks = physicalNetworks(context)
            val initialSourceIds = initialNetworks.filter { it.transport == sourceTransport && it.isValidated }.map { it.id }.toSet()
            val initialTargetIds = initialNetworks.filter { it.transport == targetTransport }.map { it.id }.toSet()
            assertTrue(
                "The active physical source network was not still validated after VPN startup",
                initialNetworks.any {
                    it.id == physicalDefaultBeforeVpn.id && it.transport == sourceTransport && it.isValidated
                }
            )
            activeVpnPhysicalTransport(context)?.let {
                assertEquals("The active VPN reports a different underlying transport", sourceTransport, it)
            }
            val oldClient = DnsVpnService.getOkHttpClient()
            val marker = "D08_HANDOFF_SWITCH_REQUIRED direction=$direction hostname=$domain phase=strict-query-issued"
            println(marker)
            Log.i(HANDOFF_LOG_TAG, marker)

            val switchedNetworks = awaitPhysicalTransportHandoff(
                context = context,
                direction = direction,
                initialSourceIds = initialSourceIds,
                initialTargetIds = initialTargetIds
            )
            assertEquals("VPN did not select the target physical transport", targetTransport, activeVpnPhysicalTransport(context))
            awaitNetworkFenceLog(baselineFenceLogs)
            val oldQueryPendingAtFence = !inflightQuery.isCompleted
            val selectedNetwork = switchedNetworks.first { it.transport == targetTransport }
            val handoffEvidence =
                "D08_HANDOFF_OBSERVED direction=$direction target=$targetTransport networkId=${selectedNetwork.id} oldQueryPendingAtFence=$oldQueryPendingAtFence"
            println(handoffEvidence)
            Log.i(HANDOFF_LOG_TAG, handoffEvidence)
            val newClient = DnsVpnService.getOkHttpClient()
            assertTrue("DoH OkHttpClient was not reset after the selected network changed", oldClient !== newClient)

            val inflightResponse = inflightQuery.await()
            if (inflightResponse != null) {
                assertDnsTransaction(inflightResponse, inflightId)
                assertDnsResponseCode(inflightResponse, 2)
                assertEquals("The in-flight strict query returned an answer", 0, dnsAnswerCount(inflightResponse))
            }

            val freshId = (inflightId + 1) and 0xffff
            val freshResponse = sendQueryThroughTunOnce(buildDnsQuery(domain, freshId, queryType = 28))
            assertNotNull("The post-handoff strict query timed out", freshResponse)
            assertDnsTransaction(requireNotNull(freshResponse), freshId)
            assertDnsResponseCode(requireNotNull(freshResponse), 2)
            assertEquals("The post-handoff strict query returned an answer", 0, dnsAnswerCount(requireNotNull(freshResponse)))
            tlsServer.assertExpectedConnectionsCompleted()
            assertEquals("Strict TLS mode sent the hostname over plaintext UDP", 0, udpServer.targetQueryCount.get())
            assertEquals(null, udpServer.failure.get())
            assertEquals("僅加密 · DoH 不可用 · SERVFAIL", DnsVpnService.dnsTransportStatusFlow.value)
            assertTrue("No validated $targetTransport network remained after handoff", switchedNetworks.any { it.transport == targetTransport })
        } finally {
            try {
                stopVpnIfRunning(context)
            } finally {
                DnsVpnService.setUiForeground(false)
                try {
                    resolverId?.let { dao.deleteDnsServerById(it) }
                    dao.getDnsServersList()
                        .filter { it.name == resolverName }
                        .forEach { dao.deleteDnsServerById(it.id) }
                    originalServers.forEach { dao.insertDnsServer(it) }
                } finally {
                    udpServer.close()
                    tlsServer.close()
                }
            }
        }
    }

    private suspend fun runTlsFailureScenario(
        allowPlaintextFallback: Boolean,
        handshakeDelayMillis: Long = 0L,
        ipv6: Boolean = false,
        namedEndpoint: Boolean = false
    ) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertTrue("This suite must run in the isolated .d08test app", context.packageName.endsWith(".d08test"))


        val dao = AppDatabase.getDatabase(context).dnsDao()
        val originalServers = dao.getDnsServersList()
        val domain = "d08-${UUID.randomUUID().toString().replace("-", "")}.example.test"
        val resolverIp = if (ipv6) "::1" else RESOLVER_IP
        val endpointHost = if (namedEndpoint) "ipv6.d08.invalid" else if (ipv6) "[$resolverIp]" else resolverIp
        val tlsServer = RejectingTlsServer(instrumentation.context, handshakeDelayMillis, resolverIp = resolverIp)
        val udpServer = FakeUdpDnsServer(domain, resolverIp)
        val resolverName = "D08 TLS ${UUID.randomUUID()}"
        var resolverId: Int? = null

        try {
            stopVpnIfRunning(context)
            dao.insertDnsServer(
                DnsServer(
                    name = resolverName,
                    primaryIp = resolverIp,
                    secondaryIp = null,
                    isCustom = true,
                    isActive = false,
                    allowPlaintextFallback = allowPlaintextFallback,
                    primaryDohUrl = "https://$endpointHost:${tlsServer.port}/dns-query",
                    primaryDohBootstrapIps = if (namedEndpoint) resolverIp else null
                )
            )
            resolverId = dao.getDnsServersList().first { it.name == resolverName }.id
            assertTrue(dao.setActiveDnsServer(requireNotNull(resolverId)))

            ensureVpnConsent(context)
            startVpn(context)
            awaitActiveVpnNetwork(context)
            // D09 debounces the initial underlay callbacks before steady-state transport assertions.
            delay(1_000)

            val transactionId = System.nanoTime().toInt() and 0xffff
            val queryStartMillis = android.os.SystemClock.elapsedRealtime()
            val response = sendQueryThroughTun(
                buildDnsQuery(domain, transactionId),
                if (ipv6) DnsVpnAddresses.IPV6_DNS else DnsVpnService.DUMMY_DNS_IP
            )
            val queryElapsedMillis = android.os.SystemClock.elapsedRealtime() - queryStartMillis

            if (handshakeDelayMillis > 0L) {
                tlsServer.assertClientConnected()
                assertTrue("Slow DoH handshake was not held long enough: ${queryElapsedMillis}ms",
                    queryElapsedMillis >= 2_000L)
            } else {
                tlsServer.assertClientRejectedCertificate()
            }
            assertDnsTransaction(response, transactionId)
            assertDnsResponseCode(response, if (allowPlaintextFallback) 0 else 2)
            val expectedTransportStatus = if (allowPlaintextFallback) {
                "UDP/53 明文降級"
            } else {
                "僅加密 · DoH 不可用 · SERVFAIL"
            }
            assertEquals(expectedTransportStatus, DnsVpnService.dnsTransportStatusFlow.value)
            if (allowPlaintextFallback) {
                assertTrue("TLS failure did not reach UDP/15353 for the test hostname", udpServer.awaitQuery())
                assertEquals("Unexpected target-host UDP query count", 1, udpServer.targetQueryCount.get())
                assertEquals(EXPECTED_ANSWER, response.takeLast(4).map { it.toInt() and 0xff })
            } else {
                assertEquals("Strict TLS mode sent the test hostname over plaintext UDP", 0, udpServer.targetQueryCount.get())
                assertEquals("Strict TLS mode must return an answerless SERVFAIL", 0, dnsAnswerCount(response))
            }
            assertEquals(null, udpServer.failure.get())
            if (allowPlaintextFallback && handshakeDelayMillis == 0L) {
                assertTransportStatusRendered(context, expectedTransportStatus)
            }
        } finally {
            try {
                stopVpnIfRunning(context)
            } finally {
                try {
                    resolverId?.let { dao.deleteDnsServerById(it) }
                    dao.getDnsServersList()
                        .filter { it.name == resolverName }
                        .forEach { dao.deleteDnsServerById(it.id) }
                    originalServers.forEach { dao.insertDnsServer(it) }
                } finally {
                    udpServer.close()
                    tlsServer.close()
                }
            }
        }
    }

    private fun assertTransportStatusRendered(context: Context, expected: String) {
        context.startActivity(
            Intent(context, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        )
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        val deadline = android.os.SystemClock.elapsedRealtime() + 5_000L
        var observed = emptyList<String>()
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            val root = automation.rootInActiveWindow
            val texts = mutableListOf<String>()
            fun collect(node: android.view.accessibility.AccessibilityNodeInfo?) {
                if (node == null || texts.size >= 40) return
                node.text?.toString()?.let(texts::add)
                for (index in 0 until node.childCount) collect(node.getChild(index))
            }
            collect(root)
            if (texts.any { expected in it }) return
            observed = texts
            Thread.sleep(100)
        }
        assertTrue("The live Compose transport card did not show $expected; visible=$observed", false)
    }

    @Suppress("DEPRECATION")
    private suspend fun ensureVpnConsent(context: Context) {
        val consentIntent = VpnService.prepare(context) ?: return
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = instrumentation.startActivitySync(
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        try {
            instrumentation.runOnMainSync { activity.startActivityForResult(consentIntent, 1) }
            withTimeout(CONSENT_TIMEOUT_MILLIS) {
                while (VpnService.prepare(context) != null) delay(250)
            }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
        }
    }

    private fun logStartupBenchmark(message: String) {
        println(message)
        Log.i(STARTUP_BENCH_LOG_TAG, message)
    }

    private suspend fun startVpn(context: Context) {
        ContextCompat.startForegroundService(
            context,
            Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
        )
        withTimeout(SERVICE_TIMEOUT_MILLIS) {
            DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING }
        }
    }

    private suspend fun awaitActiveVpnNetwork(context: Context): Network {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        return withTimeout(SERVICE_TIMEOUT_MILLIS) {
            var network: Network? = null
            while (network == null) {
                network = connectivity.activeNetwork?.takeIf {
                    connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                }
                if (network == null) delay(20)
            }
            network
        }
    }

    private suspend fun stopVpnIfRunning(context: Context) {
        if (DnsVpnService.lifecycleStateFlow.value == VpnLifecycleState.STOPPED) return
        ContextCompat.startForegroundService(
            context,
            Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)
        )
        withTimeout(SERVICE_TIMEOUT_MILLIS) {
            DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED }
        }
    }

    private suspend fun awaitD14TerminalCount(target: Long): DnsDiagnosticsSnapshot = withTimeout(SERVICE_TIMEOUT_MILLIS) {
        var snapshot = DnsVpnService.d14DiagnosticsSnapshot()
        while (snapshot.terminalCount < target) {
            delay(20)
            snapshot = DnsVpnService.d14DiagnosticsSnapshot()
        }
        snapshot
    }

    private fun sendQueryThroughTun(
        query: ByteArray,
        virtualDnsIp: String = DnsVpnService.DUMMY_DNS_IP
    ): ByteArray = DatagramSocket().use { socket ->
        socket.soTimeout = 500
        val request = DatagramPacket(query, query.size,
            InetAddress.getByName(virtualDnsIp), 53)
        val response = DatagramPacket(ByteArray(2048), 2048)
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(QUERY_TIMEOUT_MILLIS.toLong())
        while (true) {
            socket.send(request)
            try { socket.receive(response); break }
            catch (error: java.net.SocketTimeoutException) {
                if (System.nanoTime() >= deadline) throw error
            }
        }
        response.data.copyOf(response.length)
    }

    private fun sendQueryThroughTunOnce(query: ByteArray, network: Network? = null): ByteArray? = DatagramSocket().use { socket ->
        network?.bindSocket(socket)
        socket.soTimeout = QUERY_TIMEOUT_MILLIS
        socket.send(DatagramPacket(query, query.size, InetAddress.getByName(DnsVpnService.DUMMY_DNS_IP), 53))
        val response = DatagramPacket(ByteArray(2048), 2048)
        try {
            socket.receive(response)
            response.data.copyOf(response.length)
        } catch (_: SocketTimeoutException) {
            null
        }
    }

    private data class PhysicalNetwork(val id: Long, val transport: String, val isValidated: Boolean)
    private data class StartupDnsQueryResult(
        val domain: String,
        val transactionId: Int,
        val clientMillis: Long,
        val response: ByteArray?
    )

    private suspend fun awaitActivePhysicalNetwork(context: Context): PhysicalNetwork = withTimeout(SERVICE_TIMEOUT_MILLIS) {
        val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        while (true) {
            val network = connectivity.activeNetwork
            val capabilities = network?.let(connectivity::getNetworkCapabilities)
            val transport = when {
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "wifi"
                capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "cellular"
                else -> null
            }
            if (network != null && capabilities != null && transport != null &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            ) return@withTimeout PhysicalNetwork(network.networkHandle, transport, isValidated = true)
            delay(100)
        }
        throw AssertionError("No active validated physical network was available before VPN startup")
    }

    private fun activeVpnPhysicalTransport(context: Context): String? {
        val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val capabilities = connectivity.activeNetwork?.let(connectivity::getNetworkCapabilities) ?: return null
        if (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null
        return when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            else -> null
        }
    }

    @Suppress("DEPRECATION")
    private fun physicalNetworks(context: Context): List<PhysicalNetwork> {
        val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        return connectivity.allNetworks.mapNotNull { network ->
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            ) return@mapNotNull null
            val transport = when {
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                else -> return@mapNotNull null
            }
            PhysicalNetwork(
                id = network.networkHandle,
                transport = transport,
                isValidated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            )
        }
    }

    private suspend fun awaitPhysicalTransportHandoff(
        context: Context,
        direction: String,
        initialSourceIds: Set<Long>,
        initialTargetIds: Set<Long>
    ): List<PhysicalNetwork> {
        val sourceTransport = if (direction == "wifi-to-cellular") "wifi" else "cellular"
        val targetTransport = if (direction == "wifi-to-cellular") "cellular" else "wifi"
        val deadline = android.os.SystemClock.elapsedRealtime() + HANDOFF_TIMEOUT_MILLIS
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            val current = physicalNetworks(context)
            val targetAvailable = current.any { it.transport == targetTransport && it.isValidated }
            val sourceDeparted = when (direction) {
                "wifi-to-cellular" -> current.none { it.id in initialSourceIds && it.isValidated }
                else -> current.any { it.transport == targetTransport && it.id !in initialTargetIds }
            }
            if (targetAvailable && sourceDeparted) {
                delay(NETWORK_STABLE_MILLIS)
                val stable = physicalNetworks(context)
                val targetStillAvailable = stable.any { it.transport == targetTransport && it.isValidated }
                val sourceStillDeparted = when (direction) {
                    "wifi-to-cellular" -> stable.none { it.id in initialSourceIds && it.isValidated }
                    else -> stable.any { it.transport == targetTransport && it.id !in initialTargetIds && it.isValidated }
                }
                if (targetStillAvailable && sourceStillDeparted) return stable
            }
            delay(100)
        }
        throw AssertionError("The validated physical network did not switch from $sourceTransport to $targetTransport")
    }

    private fun networkFenceLogCount(): Int = DnsVpnService.liveLogsFlow.value.count {
        "網路狀態已更新，DNS 快取已清除" in it
    }

    private suspend fun awaitNetworkFenceLog(baselineCount: Int) {
        withTimeout(HANDOFF_TIMEOUT_MILLIS) {
            while (networkFenceLogCount() <= baselineCount) delay(100)
        }
    }

    private fun assertDnsTransaction(response: ByteArray, transactionId: Int) {
        assertTrue("DNS response is too short", response.size >= 12)
        val actualId = ((response[0].toInt() and 0xff) shl 8) or (response[1].toInt() and 0xff)
        assertEquals(transactionId, actualId)
        assertTrue("Packet is not a DNS response", response[2].toInt() and 0x80 != 0)
    }

    private fun assertDnsResponseCode(response: ByteArray, expected: Int) {
        val flags = ((response[2].toInt() and 0xff) shl 8) or (response[3].toInt() and 0xff)
        assertEquals(expected, flags and 0x0f)
    }

    private fun dnsAnswerCount(response: ByteArray): Int =
        ((response[6].toInt() and 0xff) shl 8) or (response[7].toInt() and 0xff)

    private fun buildDnsQuery(domain: String, transactionId: Int, queryType: Int = 1): ByteArray {
        val output = ByteArrayOutputStream()
        output.write(transactionId shr 8)
        output.write(transactionId)
        output.write(byteArrayOf(0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
        domain.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            output.write(bytes.size)
            output.write(bytes)
        }
        output.write(0)
        output.write(queryType shr 8)
        output.write(queryType)
        output.write(byteArrayOf(0x00, 0x01))
        return output.toByteArray()
    }

    private fun buildDnsResponse(query: ByteArray): ByteArray {
        val isAQuery = query.size >= 4 &&
            (query[query.size - 4].toInt() and 0xff) == 0 &&
            (query[query.size - 3].toInt() and 0xff) == 1
        val output = ByteArrayOutputStream()
        output.write(query.copyOfRange(0, 2))
        output.write(byteArrayOf(
            0x81.toByte(), 0x80.toByte(), 0, 1, 0,
            if (isAQuery) 0x01 else 0x00,
            0, 0, 0, 0
        ))
        output.write(query.copyOfRange(12, query.size))
        if (isAQuery) {
            output.write(byteArrayOf(0xc0.toByte(), 0x0c, 0x00, 0x01, 0x00, 0x01))
            output.write(byteArrayOf(0x00, 0x00, 0x00, 0x3c, 0x00, 0x04))
            output.write(byteArrayOf(192.toByte(), 0, 2, 53))
        }
        return output.toByteArray()
    }

    private fun dnsQuestionName(query: ByteArray): String? {
        if (query.size <= 12) return null
        val labels = mutableListOf<String>()
        var offset = 12
        while (offset < query.size) {
            val length = query[offset++].toInt() and 0xff
            if (length == 0) return labels.joinToString(".")
            if (length >= 64 || offset + length > query.size) return null
            labels += String(query, offset, length, Charsets.US_ASCII)
            offset += length
        }
        return null
    }

    private class RejectingTlsServer(
        testContext: Context,
        private val handshakeDelayMillis: Long,
        private val expectedConnections: Int = 1,
        resolverIp: String = RESOLVER_IP
    ) : Closeable {
        private val firstAccepted = CountDownLatch(1)
        private val allAccepted = CountDownLatch(expectedConnections)
        private val allHandshakesFinished = CountDownLatch(expectedConnections)
        private val handshakeFailure = AtomicReference<Throwable?>()
        private val handshakeSucceeded = AtomicBoolean(false)
        private val serverSocket: SSLServerSocket
        private val worker: Thread
        val port: Int
            get() = serverSocket.localPort

        init {
            val keyStore = KeyStore.getInstance("PKCS12")
            testContext.assets.open(CERT_ASSET).use { keyStore.load(it, CERT_PASSWORD.toCharArray()) }
            val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            keyManagerFactory.init(keyStore, CERT_PASSWORD.toCharArray())
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(keyManagerFactory.keyManagers, null, null)
            serverSocket = sslContext.serverSocketFactory.createServerSocket(
                0,
                expectedConnections,
                InetAddress.getByName(resolverIp)
            ) as SSLServerSocket
            worker = Thread {
                for (connectionIndex in 0 until expectedConnections) {
                    var client: SSLSocket? = null
                    try {
                        client = serverSocket.accept() as SSLSocket
                        firstAccepted.countDown()
                        allAccepted.countDown()
                        client.soTimeout = SERVER_TIMEOUT_MILLIS
                        if (connectionIndex == 0 && handshakeDelayMillis > 0L) Thread.sleep(handshakeDelayMillis)
                        client.startHandshake()
                        handshakeSucceeded.set(true)
                    } catch (_: InterruptedException) {
                        // The test closed the server while the controlled handshake delay was active.
                        break
                    } catch (exception: SSLException) {
                        handshakeFailure.set(exception)
                    } catch (exception: IOException) {
                        if (!serverSocket.isClosed) handshakeFailure.set(exception)
                    } finally {
                        try {
                            client?.close()
                        } catch (_: IOException) {
                        }
                        allHandshakesFinished.countDown()
                    }
                }
            }.apply {
                name = "d08-rejecting-tls-server"
                isDaemon = true
                start()
            }
        }

        fun assertClientConnected() {
            assertTrue("DoH client never connected to the local TLS endpoint",
                firstAccepted.await(SERVER_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS))
        }

        fun assertClientRejectedCertificate() {
            assertClientConnected()
            assertTrue("TLS handshake did not finish after the test certificate was presented",
                allHandshakesFinished.await(SERVER_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS))
            assertFalse("The client accepted the untrusted test certificate", handshakeSucceeded.get())
            assertNotNull("Expected the client to reject the self-signed test certificate", handshakeFailure.get())
        }

        fun assertExpectedConnectionsCompleted() {
            assertTrue("Post-handoff DoH did not open a fresh TLS connection",
                allAccepted.await(SERVER_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS))
            assertTrue("TLS handshakes did not finish after the network handoff",
                allHandshakesFinished.await(SERVER_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS))
            assertFalse("The client accepted the untrusted test certificate", handshakeSucceeded.get())
            assertNotNull("Expected the client to reject the self-signed test certificate", handshakeFailure.get())
        }

        override fun close() {
            try {
                serverSocket.close()
            } catch (_: IOException) {
            }
            worker.interrupt()
            worker.join(1_000)
        }
    }

    private inner class FakeUdpDnsServer(
        private val expectedDomain: String,
        resolverIp: String = RESOLVER_IP
    ) : Closeable {
        private val running = AtomicBoolean(true)
        private val requestReceived = CountDownLatch(1)
        private val socket = DatagramSocket(null).apply {
            reuseAddress = true
            bind(InetSocketAddress(InetAddress.getByName(resolverIp), BuildConfig.DNS_UPSTREAM_PORT))
            soTimeout = 200
        }
        val targetQueryCount = AtomicInteger(0)
        val backgroundQueryCount = AtomicInteger(0)
        val failure = AtomicReference<IOException?>()
        private val worker = Thread {
            while (running.get()) {
                val packet = DatagramPacket(ByteArray(2048), 2048)
                try {
                    socket.receive(packet)
                    val query = packet.data.copyOf(packet.length)
                    if (dnsQuestionName(query)?.equals(expectedDomain, ignoreCase = true) == true) {
                        targetQueryCount.incrementAndGet()
                        requestReceived.countDown()
                    } else {
                        backgroundQueryCount.incrementAndGet()
                    }
                    val response = buildDnsResponse(query)
                    socket.send(DatagramPacket(response, response.size, packet.socketAddress))
                } catch (_: SocketTimeoutException) {
                    // Recheck the close flag.
                } catch (exception: IOException) {
                    if (running.get()) failure.set(exception)
                }
            }
        }.apply {
            name = "d08-fake-udp-dns"
            isDaemon = true
            start()
        }

        fun awaitQuery(): Boolean = requestReceived.await(QUERY_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)

        override fun close() {
            running.set(false)
            socket.close()
            worker.join(1_000)
        }
    }

    companion object {
        private const val RESOLVER_IP = "127.0.0.2"
        private const val CERT_ASSET = "d08-test-server.p12"
        private const val CERT_PASSWORD = "d08-test-only-password"
        private const val QUERY_TIMEOUT_MILLIS = 12_000
        private const val SERVER_TIMEOUT_MILLIS = 8_000
        private const val SERVICE_TIMEOUT_MILLIS = 30_000L
        private const val HANDOFF_TIMEOUT_MILLIS = 30_000L
        private const val NETWORK_STABLE_MILLIS = 500L
        private const val HANDOFF_LOG_TAG = "D08_HANDOFF"
        private const val STARTUP_BENCH_LOG_TAG = "D08_STARTUP_BENCH"
        private const val CONSENT_TIMEOUT_MILLIS = 120_000L
        private val EXPECTED_ANSWER = listOf(192, 0, 2, 53)
    }
}
