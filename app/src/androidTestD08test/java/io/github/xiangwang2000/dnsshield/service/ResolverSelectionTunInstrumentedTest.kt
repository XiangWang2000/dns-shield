package io.github.xiangwang2000.dnsshield.service

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.DnsServer
import io.github.xiangwang2000.dnsshield.viewmodel.DnsVpnViewModel
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ResolverSelectionTunInstrumentedTest {
    @Test
    fun latestViewModelSelectionWinsThroughRoomServiceAndTun() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertTrue("Run only in the isolated D08 test package", context.packageName.endsWith(".d08test"))
        assertEquals(15353, BuildConfig.DNS_UPSTREAM_PORT)
        assertNull("Approve VPN consent for .d08test before this run", VpnService.prepare(context))

        val dao = AppDatabase.getDatabase(context).dnsDao()
        val originalActive = dao.getActiveDnsServer()
        val suffix = UUID.randomUUID().toString().replace("-", "")
        val nameA = "D08 resolver A $suffix"
        val nameB = "D08 resolver B $suffix"
        val nameC = "D08 inactive resolver $suffix"
        val domainInitialB = "d08-b-$suffix.example.test"
        val domainSelectedA = "d08-a-$suffix.example.test"
        val domainAfterLateUpdate = "d08-late-$suffix.example.test"
        val domains = setOf(domainInitialB, domainSelectedA, domainAfterLateUpdate)
        val testStore = ViewModelStore()
        val owner = object : ViewModelStoreOwner {
            override val viewModelStore = testStore
        }
        lateinit var viewModel: DnsVpnViewModel
        instrumentation.runOnMainSync {
            viewModel = ViewModelProvider(
                owner,
                ViewModelProvider.AndroidViewModelFactory.getInstance(context.applicationContext as Application)
            )[DnsVpnViewModel::class.java]
        }

        var releaseBarrier: CompletableDeferred<Boolean>? = null
        var barrierResult: kotlinx.coroutines.Deferred<Boolean>? = null
        var upstreamA: FakeUdpDnsUpstream? = null
        var upstreamB: FakeUdpDnsUpstream? = null
        var resolverA: DnsServer? = null
        var resolverB: DnsServer? = null
        var resolverC: DnsServer? = null
        var activeMonitor: kotlinx.coroutines.Job? = null

        try {
            stopVpnIfRunning(context)
            upstreamA = FakeUdpDnsUpstream(
                ip = "127.0.0.2",
                targetDomains = domains,
                answer = byteArrayOf(192.toByte(), 0, 2, 11)
            )
            upstreamB = FakeUdpDnsUpstream(
                ip = "127.0.0.3",
                targetDomains = domains,
                answer = byteArrayOf(192.toByte(), 0, 2, 22)
            )

            dao.insertDnsServer(
                DnsServer(name = nameA, primaryIp = "127.0.0.2", secondaryIp = null, isCustom = true)
            )
            dao.insertDnsServer(
                DnsServer(name = nameB, primaryIp = "127.0.0.3", secondaryIp = null, isCustom = true)
            )
            dao.insertDnsServer(
                DnsServer(
                    name = nameC,
                    primaryIp = "127.0.0.4",
                    secondaryIp = null,
                    isCustom = true,
                    allowPlaintextFallback = false
                )
            )
            resolverA = dao.getDnsServersList().first { it.name == nameA }
            resolverB = dao.getDnsServersList().first { it.name == nameB }
            resolverC = dao.getDnsServersList().first { it.name == nameC }
            assertFalse(requireNotNull(resolverC).isActive)
            assertTrue(dao.setActiveDnsServer(requireNotNull(resolverB).id))

            DnsVpnService.setUiForeground(true)
            DnsVpnService.clearLogs()
            startVpn(context)
            awaitActiveVpnNetwork(context)
            withTimeout(SERVICE_TIMEOUT_MILLIS) {
                DnsVpnService.liveLogsFlow.first { lines ->
                    lines.any { "[網路狀態] 網路連線正常" in it }
                }
            }
            withTimeout(SERVICE_TIMEOUT_MILLIS) {
                DnsVpnService.activeDnsFlow.first { it == resolverLabel(requireNotNull(resolverB)) }
            }
            withTimeout(SERVICE_TIMEOUT_MILLIS) {
                viewModel.activeDnsServer.first { it?.id == resolverB.id }
            }

            val initialQuery = dnsQuery(domainInitialB, 0x8101)
            val initialResponse = sendThroughTun(initialQuery)
            assertDnsAnswer(initialQuery, initialResponse, byteArrayOf(192.toByte(), 0, 2, 22))
            assertTrue(requireNotNull(upstreamB).targetCount(domainInitialB) > 0)
            assertEquals(0, requireNotNull(upstreamA).targetCount(domainInitialB))

            val barrierEntered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Boolean>()
            releaseBarrier = release
            val coordinatorBarrier = ResolverCommandRuntime.coordinator.submit {
                barrierEntered.complete(Unit)
                release.await()
            }
            barrierResult = coordinatorBarrier.result
            withTimeout(5_000) { barrierEntered.await() }
            val selectionBase = ResolverCommandRuntime.revisions.next()
            val staleBRevision = selectionBase + 2L
            val finalSelectionRevision = selectionBase + 4L
            instrumentation.runOnMainSync {
                viewModel.selectDnsServer(requireNotNull(resolverA).id)
                viewModel.selectDnsServer(requireNotNull(resolverB).id)
                viewModel.selectDnsServer(requireNotNull(resolverA).id)
                viewModel.setPlaintextFallback(requireNotNull(resolverC), true)
            }
            assertTrue(ResolverCommandRuntime.revisions.isCurrent(finalSelectionRevision))

            val queuedSelectionFence = ResolverCommandRuntime.coordinator.submitReceived(
                requestedRevision = finalSelectionRevision
            ) { true }
            release.complete(true)
            assertTrue(withTimeout(COMMAND_TIMEOUT_MILLIS) { requireNotNull(barrierResult).await() })
            assertTrue(withTimeout(COMMAND_TIMEOUT_MILLIS) { queuedSelectionFence.result.await() })
            val activeA = requireNotNull(dao.getActiveDnsServer())
            assertEquals(resolverA.id, activeA.id)
            assertTrue(dao.getDnsServerById(requireNotNull(resolverC).id)?.allowPlaintextFallback == true)

            val displayA = resolverLabel(requireNotNull(resolverA))
            withTimeout(SERVICE_TIMEOUT_MILLIS) { DnsVpnService.activeDnsFlow.first { it == displayA } }
            withTimeout(SERVICE_TIMEOUT_MILLIS) { viewModel.activeDns.first { it == displayA } }
            withTimeout(SERVICE_TIMEOUT_MILLIS) {
                viewModel.activeDnsServer.first { it?.id == resolverA.id }
            }

            val selectedQuery = dnsQuery(domainSelectedA, 0x8102)
            val selectedResponse = sendThroughTun(selectedQuery)
            assertDnsAnswer(selectedQuery, selectedResponse, byteArrayOf(192.toByte(), 0, 2, 11))
            assertTrue(requireNotNull(upstreamA).targetCount(domainSelectedA) > 0)
            assertEquals(0, requireNotNull(upstreamB).targetCount(domainSelectedA))

            val activeEmissions = CopyOnWriteArrayList<String>()
            activeMonitor = launch { DnsVpnService.activeDnsFlow.collect(activeEmissions::add) }
            val barrierName = "$nameA actor barrier"
            dao.insertDnsServer(activeA.copy(name = barrierName))
            DnsVpnService.setUiForeground(true)
            DnsVpnService.clearLogs()
            context.startService(updateIntent(requireNotNull(resolverB).id, staleBRevision))
            val actorBarrierRevision = ResolverCommandRuntime.revisions.next()
            context.startService(updateIntent(requireNotNull(resolverA).id, actorBarrierRevision))
            val barrierDisplay = "${barrierName} (${resolverA.primaryIp})"
            withTimeout(SERVICE_TIMEOUT_MILLIS) {
                DnsVpnService.activeDnsFlow.first { it == barrierDisplay }
            }
            val barrierLog = "已即時套用新 DNS 設定：$barrierName"
            val barrierLogCount = withTimeout(5_000L) {
                var previousCount = -1
                var stableSince = SystemClock.elapsedRealtime()
                while (true) {
                    val count = DnsVpnService.liveLogsFlow.value.count { barrierLog in it }
                    val now = SystemClock.elapsedRealtime()
                    if (count != previousCount) {
                        previousCount = count
                        stableSince = now
                    } else if (count > 0 && now - stableSince >= 400L) {
                        return@withTimeout count
                    }
                    kotlinx.coroutines.delay(50)
                }
                error("unreachable")
            }
            assertEquals("The stale B command was applied before the actor barrier", 1, barrierLogCount)
            activeMonitor.cancelAndJoin()
            activeMonitor = null
            assertFalse("Late B intent changed the live resolver", activeEmissions.contains(resolverLabel(requireNotNull(resolverB))))

            dao.insertDnsServer(activeA)
            val restoreRevision = ResolverCommandRuntime.revisions.next()
            context.startService(updateIntent(requireNotNull(resolverA).id, restoreRevision))
            withTimeout(SERVICE_TIMEOUT_MILLIS) {
                DnsVpnService.activeDnsFlow.first { it == displayA }
            }

            val finalQuery = dnsQuery(domainAfterLateUpdate, 0x8103)
            val finalResponse = sendThroughTun(finalQuery)
            assertDnsAnswer(finalQuery, finalResponse, byteArrayOf(192.toByte(), 0, 2, 11))
            assertTrue(requireNotNull(upstreamA).targetCount(domainAfterLateUpdate) > 0)
            assertEquals(0, requireNotNull(upstreamB).targetCount(domainAfterLateUpdate))
            assertEquals(resolverA.id, dao.getActiveDnsServer()?.id)
            assertEquals(displayA, viewModel.activeDns.value)
            assertEquals(displayA, DnsVpnService.activeDnsFlow.value)
            assertNull(requireNotNull(upstreamA).failure.get())
            assertNull(requireNotNull(upstreamB).failure.get())
        } finally {
            releaseBarrier?.complete(true)
            runCatching {
                withTimeout(COMMAND_TIMEOUT_MILLIS) {
                    barrierResult?.await()
                    ResolverCommandRuntime.coordinator.awaitPriorCommands()
                }
            }
            activeMonitor?.cancelAndJoin()
            DnsVpnService.setUiForeground(false)
            try {
                stopVpnIfRunning(context)
            } finally {
                try {
                    if (originalActive == null) {
                        dao.deactivateOtherDns(-1)
                    } else if (dao.getDnsServerById(originalActive.id) != null) {
                        dao.setActiveDnsServer(originalActive.id)
                    }
                    listOfNotNull(resolverA, resolverB, resolverC)
                        .forEach { dao.deleteDnsServerById(it.id) }
                    dao.getDnsServersList()
                        .filter { it.name == nameA || it.name == nameB || it.name == nameC }
                        .forEach { dao.deleteDnsServerById(it.id) }
                } finally {
                    upstreamA?.close()
                    upstreamB?.close()
                    instrumentation.runOnMainSync { testStore.clear() }
                }
            }
        }
    }

    private fun updateIntent(resolverId: Int, revision: Long) =
        Intent(InstrumentationRegistry.getInstrumentation().targetContext, DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_UPDATE_DNS
            putExtra("resolverId", resolverId)
            putExtra(DnsVpnService.EXTRA_RESOLVER_COMMAND_REVISION, revision)
        }

    private fun resolverLabel(server: DnsServer): String = "${server.name} (${server.primaryIp})"

    private suspend fun startVpn(context: Context) {
        ContextCompat.startForegroundService(
            context,
            Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
        )
        withTimeout(SERVICE_TIMEOUT_MILLIS) {
            DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.RUNNING }
        }
    }

    private suspend fun stopVpnIfRunning(context: Context) {
        if (DnsVpnService.lifecycleStateFlow.value == VpnLifecycleState.STOPPED) return
        context.startService(
            Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP)
        )
        withTimeout(SERVICE_TIMEOUT_MILLIS) {
            DnsVpnService.lifecycleStateFlow.first { it == VpnLifecycleState.STOPPED }
        }
    }

    private suspend fun awaitActiveVpnNetwork(context: Context) {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        withTimeout(SERVICE_TIMEOUT_MILLIS) {
            while (connectivity.activeNetwork?.let(connectivity::getNetworkCapabilities)
                    ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != true
            ) {
                kotlinx.coroutines.delay(100)
            }
        }
    }

    private fun dnsQuery(domain: String, transactionId: Int): ByteArray =
        ByteArrayOutputStream().also { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeShort(transactionId)
                output.writeShort(0x0100)
                output.writeShort(1)
                repeat(3) { output.writeShort(0) }
                domain.split('.').forEach { label ->
                    output.writeByte(label.length)
                    output.write(label.toByteArray(Charsets.US_ASCII))
                }
                output.writeByte(0)
                output.writeShort(1)
                output.writeShort(1)
            }
        }.toByteArray()

    private fun sendThroughTun(query: ByteArray): ByteArray = DatagramSocket().use { client ->
        client.soTimeout = 500
        client.connect(InetAddress.getByName(DnsVpnService.DUMMY_DNS_IP), 53)
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10)
        while (true) {
            client.send(DatagramPacket(query, query.size))
            val packet = DatagramPacket(ByteArray(4096), 4096)
            try {
                client.receive(packet)
                return@use packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
            } catch (exception: SocketTimeoutException) {
                if (System.nanoTime() >= deadline) throw AssertionError("TUN query timed out", exception)
            } catch (exception: SocketException) {
                throw AssertionError("VPN TUN socket closed during query", exception)
            }
        }
        error("unreachable")
    }

    private fun assertDnsAnswer(query: ByteArray, response: ByteArray, expectedAddress: ByteArray) {
        val parsed = DnsMessageValidator.parseQuery(query) as DnsQueryParseResult.Valid
        assertTrue("Invalid DNS response", DnsMessageValidator.isValidResponse(response, parsed.query))
        assertEquals(1, (response[6].toInt() and 0xff) shl 8 or (response[7].toInt() and 0xff))
        assertArrayEquals(expectedAddress, response.takeLast(4).toByteArray())
    }

    private class FakeUdpDnsUpstream(
        ip: String,
        private val targetDomains: Set<String>,
        private val answer: ByteArray
    ) : Closeable {
        private val running = AtomicBoolean(true)
        private val socket = DatagramSocket(null).apply {
            reuseAddress = true
            bind(InetSocketAddress(InetAddress.getByName(ip), BuildConfig.DNS_UPSTREAM_PORT))
            soTimeout = 200
        }
        private val targetCounts = ConcurrentHashMap<String, AtomicInteger>()
        val failure = AtomicReference<Throwable?>()
        private val worker = Thread(::serve).apply {
            name = "d08-resolver-selection-$ip"
            isDaemon = true
            start()
        }

        fun targetCount(domain: String): Int = targetCounts[domain]?.get() ?: 0

        private fun serve() {
            while (running.get()) {
                val packet = DatagramPacket(ByteArray(2048), 2048)
                try {
                    socket.receive(packet)
                    val query = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    val question = dnsQuestion(query)
                    val isTarget = question != null &&
                        question.first in targetDomains && question.second == 1
                    if (isTarget) {
                        targetCounts.computeIfAbsent(requireNotNull(question).first) { AtomicInteger() }.incrementAndGet()
                    }
                    val response = dnsResponse(query, if (isTarget) answer else null)
                    socket.send(DatagramPacket(response, response.size, packet.socketAddress))
                } catch (_: SocketTimeoutException) {
                    // Recheck the close flag.
                } catch (exception: IOException) {
                    if (running.get()) failure.set(exception)
                } catch (exception: Exception) {
                    if (running.get()) failure.set(exception)
                }
            }
        }

        override fun close() {
            running.set(false)
            socket.close()
            worker.join(1_000)
            assertFalse("Fake DNS socket worker did not stop", worker.isAlive)
        }

        private fun dnsResponse(query: ByteArray, address: ByteArray?): ByteArray {
            val response = ByteArrayOutputStream()
            val header = ByteArray(12)
            query.copyInto(header, endIndex = minOf(2, query.size))
            header[2] = 0x81.toByte()
            header[3] = if (address == null) 0x82.toByte() else 0x80.toByte()
            header[5] = 1
            header[7] = if (address == null) 0 else 1
            response.write(header)
            if (query.size > 12) response.write(query, 12, query.size - 12)
            if (address != null) {
                response.write(byteArrayOf(
                    0xc0.toByte(), 0x0c, 0, 1, 0, 1,
                    0, 0, 0, 60, 0, 4
                ))
                response.write(address)
            }
            return response.toByteArray()
        }

        private fun dnsQuestion(query: ByteArray): Pair<String, Int>? {
            if (query.size < 17) return null
            val labels = mutableListOf<String>()
            var offset = 12
            while (offset < query.size) {
                val length = query[offset++].toInt() and 0xff
                if (length == 0) {
                    if (offset + 3 >= query.size) return null
                    val type = ((query[offset].toInt() and 0xff) shl 8) or
                        (query[offset + 1].toInt() and 0xff)
                    return labels.joinToString(".") to type
                }
                if (length >= 64 || offset + length > query.size) return null
                labels += String(query, offset, length, Charsets.US_ASCII)
                offset += length
            }
            return null
        }
    }

    companion object {
        private const val SERVICE_TIMEOUT_MILLIS = 30_000L
        private const val COMMAND_TIMEOUT_MILLIS = 20_000L
    }
}
