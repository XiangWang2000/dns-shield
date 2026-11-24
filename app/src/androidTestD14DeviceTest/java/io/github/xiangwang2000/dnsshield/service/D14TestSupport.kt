package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.SystemClock
import io.github.xiangwang2000.dnsshield.D14VpnConsentActivity
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue

/** Shared loopback upstream and TUN client helpers for isolated D14 instrumentation. */
internal class FakeDnsUpstream : AutoCloseable {
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
    val answeredDomains = ConcurrentHashMap.newKeySet<String>()
    val answerGates = ConcurrentHashMap<String, CountDownLatch>()
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
                answerGates[domain]?.let { gate ->
                    check(gate.await(95, TimeUnit.SECONDS)) { "Delayed answer gate was never released" }
                }
                val delay = if (delayDomain == domain) delayMillis else 0L
                if (delay > 0L) Thread.sleep(delay)
                val response = buildAnswer(query)
                socket.send(DatagramPacket(response, response.size, packet.address, packet.port))
                answeredDomains.add(domain)
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

internal const val D14_VPN_CONSENT_TIMEOUT_MS = 120_000L

internal fun ensureD14VpnConsent(context: Context) {
    if (VpnService.prepare(context) == null) return
    context.startActivity(
        Intent(context, D14VpnConsentActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    )
    val deadline = SystemClock.elapsedRealtime() + D14_VPN_CONSENT_TIMEOUT_MS
    while (SystemClock.elapsedRealtime() < deadline) {
        if (VpnService.prepare(context) == null) return
        SystemClock.sleep(250L)
    }
    assertEquals(
        "Approve the Android VPN consent prompt for the isolated .d14test package to continue.",
        null,
        VpnService.prepare(context)
    )
}

internal fun d14WaitForLifecycle(expected: VpnLifecycleState, timeoutMillis: Long) {
    val deadline = SystemClock.elapsedRealtime() + timeoutMillis
    while (SystemClock.elapsedRealtime() < deadline) {
        val state = DnsVpnService.lifecycleStateFlow.value
        if (state == expected) return
        if (state == VpnLifecycleState.FAILED) {
            throw AssertionError("DNS VPN service entered FAILED while waiting for $expected")
        }
        SystemClock.sleep(25L)
    }
    throw AssertionError(
        "Timed out waiting for VPN lifecycle $expected; current=${DnsVpnService.lifecycleStateFlow.value}"
    )
}

internal fun d14BuildQuery(domain: String, transactionId: Int): ByteArray {
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

internal fun d14ResponseCode(response: ByteArray): Int {
    assertTrue("DNS response is too short.", response.size >= 4)
    return response[3].toInt() and 0x0F
}

internal fun d14SendQuery(domain: String, transactionId: Int, timeoutMillis: Int = 7_000): ByteArray {
    val query = d14BuildQuery(domain, transactionId)
    DatagramSocket().use { socket ->
        socket.soTimeout = timeoutMillis
        socket.send(DatagramPacket(query, query.size, InetAddress.getByName(DnsVpnService.DUMMY_DNS_IP), 53))
        val buffer = ByteArray(2_048)
        val response = DatagramPacket(buffer, buffer.size)
        socket.receive(response)
        val payload = response.data.copyOfRange(response.offset, response.offset + response.length)
        assertEquals(
            "DNS transaction ID was rewritten.",
            transactionId,
            ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF)
        )
        return payload
    }
}

internal fun d14AssertDnsAnswer(response: ByteArray) {
    assertTrue("DNS response is too short.", response.size >= 12)
    assertTrue("Expected DNS QR bit.", (response[2].toInt() and 0x80) != 0)
    assertEquals("Expected NOERROR.", 0, d14ResponseCode(response))
    assertEquals("Expected one answer record.", 1, unsignedShort(response, 6))
}

internal fun d14AwaitRcode(domain: String, expected: Int, timeoutMillis: Long = 15_000L): ByteArray {
    val deadline = SystemClock.elapsedRealtime() + timeoutMillis
    var lastRcode: Int? = null
    while (SystemClock.elapsedRealtime() < deadline) {
        try {
            val response = d14SendQuery(domain, 0x9100)
            lastRcode = d14ResponseCode(response)
            if (lastRcode == expected) return response
        } catch (_: SocketTimeoutException) {
            // The service may still be installing the reloaded policy; retry until the deadline.
        }
        SystemClock.sleep(50L)
    }
    throw AssertionError("Expected DNS RCODE $expected after live rule reload; last response RCODE was $lastRcode")
}

internal fun unsignedShort(bytes: ByteArray, offset: Int): Int =
    ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
