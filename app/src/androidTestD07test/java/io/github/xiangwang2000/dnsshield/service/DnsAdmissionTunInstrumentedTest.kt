package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Debug
import android.os.SystemClock
import android.system.Os
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Device acceptance for D05 through an actual Android VPN TUN. */
@RunWith(AndroidJUnit4::class)
class DnsAdmissionTunInstrumentedTest {
    @Test
    fun boundedTunLoadDeadlineFallbackAndPendingStop() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("io.github.xiangwang2000.dnsshield.d07test", context.packageName)
        assertEquals(15353, BuildConfig.DNS_UPSTREAM_PORT)
        assertNull("Approve the isolated VPN before this test.", VpnService.prepare(context))

        val upstream = FakeUpstream()
        val workers = Executors.newFixedThreadPool(50)
        val run = SystemClock.elapsedRealtime().toString(36)
        var started = false
        try {
            ContextCompat.startForegroundService(
                context,
                Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
            )
            started = true
            awaitState(15_000) { DnsVpnService.lifecycleStateFlow.value == VpnLifecycleState.RUNNING }
            val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            awaitState(10_000) {
                connectivity.activeNetwork?.let { network ->
                    connectivity.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                } == true
            }
            updateDns(context, "127.0.0.1", null)
            val heapBefore = usedHeap()
            val pssBefore = Debug.getPss()

            val burst = (0 until 40).map { index -> "d05-burst-$run-$index.example.com" }
            val gate = CountDownLatch(1)
            val burstSent = CountDownLatch(burst.size)
            val burstFutures = burst.mapIndexed { index, domain ->
                workers.submit(Callable {
                    assertTrue(gate.await(5, TimeUnit.SECONDS))
                    query(domain, 0x5000 + index, burstSent)
                })
            }
            gate.countDown()
            assertTrue("Burst clients did not send together", burstSent.await(3, TimeUnit.SECONDS))
            awaitState(2_000) { burst.sumOf(upstream::count) >= 20 }
            Thread.sleep(150)
            val heapAtBurst = usedHeap()
            val pssAtBurst = Debug.getPss()
            val overflow = query("d05-overflow-$run.example.com", 0x5100)
            assertRcode(overflow, 0x5100, 2)
            assertTrue("Unique-key overload was not immediate: ${overflow.millis} ms", overflow.millis < 1_500)
            assertEquals(0, upstream.count("d05-overflow-$run.example.com"))
            burstFutures.forEachIndexed { index, future ->
                assertRcode(future.get(8, TimeUnit.SECONDS), 0x5000 + index, 2)
            }
            val upstreamBurst = burst.sumOf(upstream::count)
            println("D05_BURST_UPSTREAM=$upstreamBurst/${burst.size}")
            assertTrue("More than 24 unique upstream leaders: $upstreamBurst", upstreamBurst <= 24)

            val shared = "d05-shared-$run.example.com"
            val leader = workers.submit(Callable { query(shared, 0x5200) })
            awaitState(2_000) { upstream.count(shared) == 1 }
            val sent = CountDownLatch(8)
            val waiters = (0 until 8).map { index ->
                workers.submit(Callable { query(shared, 0x5201 + index, sent) })
            }
            assertTrue(sent.await(2, TimeUnit.SECONDS))
            Thread.sleep(200)
            val excessWaiter = query(shared, 0x5209)
            assertRcode(excessWaiter, 0x5209, 2)
            assertTrue("Same-key overload was not immediate: ${excessWaiter.millis} ms", excessWaiter.millis < 1_500)
            assertRcode(leader.get(8, TimeUnit.SECONDS), 0x5200, 2)
            waiters.forEachIndexed { index, future ->
                val reply = future.get(8, TimeUnit.SECONDS)
                assertRcode(reply, 0x5201 + index, 2)
                assertTrue("Admitted waiter $index was rejected immediately", reply.millis > 1_500)
            }
            assertEquals("Waiters must share one upstream request", 1, upstream.count(shared))

            upstream.respond.set(true)
            val recovered = query("d05-recovered-$run.example.com", 0x5300)
            assertRcode(recovered, 0x5300, 0)
            assertEquals(1, upstream.count("d05-recovered-$run.example.com"))

            updateDns(context, "127.0.0.2", "127.0.0.1")
            val secondary = query("d05-secondary-$run.example.com", 0x5301)
            assertRcode(secondary, 0x5301, 0)
            assertEquals(1, upstream.count("d05-secondary-$run.example.com"))

            updateDns(context, "127.0.0.1", null)
            upstream.respond.set(false)
            val pendingDomain = "d05-stop-$run.example.com"
            val pending = workers.submit(Callable { query(pendingDomain, 0x5400, timeoutMillis = 3_000) })
            awaitState(2_000) { upstream.count(pendingDomain) == 1 }
            val stopAt = SystemClock.elapsedRealtime()
            context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
            awaitState(3_000) { DnsVpnService.lifecycleStateFlow.value == VpnLifecycleState.STOPPED }
            val stopMillis = SystemClock.elapsedRealtime() - stopAt
            assertTrue("Stop waited for the UDP timeout: $stopMillis ms", stopMillis < 2_500)
            try {
                pending.get(4, TimeUnit.SECONDS)
            } catch (exception: ExecutionException) {
                assertTrue("Unexpected pending-client failure", exception.cause is SocketTimeoutException)
            }
            awaitState(2_000) { tunDescriptorCount() == 0 }
            println("D05_TUN_RESULT=40 unique attempts, at most 24 upstream, 8 waiters, overload SERVFAIL, deadline SERVFAIL, secondary fallback, pending stop ${stopMillis}ms, TUN FDs 0")
            println("D05_RESOURCES=heap $heapBefore/$heapAtBurst/${usedHeap()} bytes, PSS $pssBefore/$pssAtBurst/${Debug.getPss()} KB, FDs ${File("/proc/self/fd").list()?.size}")
        } finally {
            if (started) {
                context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
            }
            workers.shutdownNow()
            upstream.close()
        }
    }

    private fun updateDns(context: Context, primary: String, secondary: String?) {
        context.startService(Intent(context, DnsVpnService::class.java)
            .setAction(DnsVpnService.ACTION_UPDATE_DNS)
            .putExtra("primary", primary)
            .putExtra("secondary", secondary)
            .putExtra("dnsName", "D05 fake upstream"))
        awaitState(2_000) { DnsVpnService.activeDnsFlow.value == "D05 fake upstream ($primary)" }
    }

    private fun awaitState(timeoutMillis: Long, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            if (condition()) return
            Thread.sleep(20)
        }
        assertTrue("Timed out waiting for device state", condition())
    }

    private data class Result(val response: ByteArray, val millis: Long)

    private fun query(
        domain: String,
        id: Int,
        sent: CountDownLatch? = null,
        timeoutMillis: Int = 8_000
    ): Result = DatagramSocket().use { socket ->
        socket.soTimeout = timeoutMillis
        val payload = ByteArrayOutputStream().also { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeShort(id)
                output.writeShort(0x0100)
                output.writeShort(1)
                repeat(3) { output.writeShort(0) }
                domain.split('.').forEach { label ->
                    val encoded = label.toByteArray(Charsets.US_ASCII)
                    output.writeByte(encoded.size)
                    output.write(encoded)
                }
                output.writeByte(0)
                output.writeShort(1)
                output.writeShort(1)
            }
        }.toByteArray()
        val startedAt = SystemClock.elapsedRealtime()
        socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName(DnsVpnService.DUMMY_DNS_IP), 53))
        sent?.countDown()
        val reply = DatagramPacket(ByteArray(4096), 4096)
        socket.receive(reply)
        Result(reply.data.copyOfRange(reply.offset, reply.offset + reply.length), SystemClock.elapsedRealtime() - startedAt)
    }

    private fun assertRcode(result: Result, id: Int, rcode: Int) {
        val bytes = result.response
        assertTrue(bytes.size >= 12)
        assertEquals(id, ((bytes[0].toInt() and 255) shl 8) or (bytes[1].toInt() and 255))
        assertEquals(rcode, bytes[3].toInt() and 15)
    }

    private fun usedHeap(): Long = Runtime.getRuntime().let { it.totalMemory() - it.freeMemory() }

    private fun tunDescriptorCount(): Int = File("/proc/self/fd").listFiles().orEmpty().count { fd ->
        runCatching { Os.readlink(fd.path).contains("/dev/tun") }.getOrDefault(false)
    }

    private class FakeUpstream : AutoCloseable {
        private val socket = DatagramSocket(null).apply {
            bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), BuildConfig.DNS_UPSTREAM_PORT))
            soTimeout = 200
        }
        val respond = AtomicBoolean(false)
        private val counts = ConcurrentHashMap<String, AtomicInteger>()
        private val thread = Thread({
            while (!socket.isClosed) {
                try {
                    val packet = DatagramPacket(ByteArray(4096), 4096)
                    socket.receive(packet)
                    val query = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    counts.computeIfAbsent(questionName(query)) { AtomicInteger() }.incrementAndGet()
                    if (respond.get()) {
                        val answer = query.copyOf(query.size + 16)
                        answer[2] = 0x81.toByte()
                        answer[3] = 0x80.toByte()
                        answer[6] = 0
                        answer[7] = 1
                        val rr = byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192.toByte(), 0, 2, 1)
                        System.arraycopy(rr, 0, answer, query.size, rr.size)
                        socket.send(DatagramPacket(answer, answer.size, packet.socketAddress))
                    }
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (_: SocketException) {
                    if (!socket.isClosed) throw AssertionError("Fake upstream socket failed")
                }
            }
        }, "d05-fake-upstream").apply { isDaemon = true; start() }

        fun count(domain: String): Int = counts[domain]?.get() ?: 0

        override fun close() {
            socket.close()
            thread.join(1_000)
        }

        private fun questionName(bytes: ByteArray): String {
            var offset = 12
            val labels = mutableListOf<String>()
            while (offset < bytes.size) {
                val length = bytes[offset++].toInt() and 255
                if (length == 0) return labels.joinToString(".")
                if (length > 63 || offset + length > bytes.size) return "invalid"
                labels += String(bytes, offset, length, Charsets.US_ASCII)
                offset += length
            }
            return "invalid"
        }
    }
}
