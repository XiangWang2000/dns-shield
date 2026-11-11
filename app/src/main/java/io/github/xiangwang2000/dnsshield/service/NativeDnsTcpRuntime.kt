package io.github.xiangwang2000.dnsshield.service

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.Closeable
import java.io.FileDescriptor
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

internal object NativeDnsTcp {
    init { System.loadLibrary("dns-shield-tcp") }
    external fun run(config: String, fd: Int): Int
    external fun stop()
}

/** One packet socket feeds the native TCP stack; the service remains the sole TUN reader. */
internal class NativeDnsTcpRuntime(
    handler: (ByteArray, (ByteArray) -> Unit) -> Unit,
    private val sendPacket: (ByteArray) -> Unit,
    private val onFailure: () -> Unit
) : Closeable {
    private val stopping = AtomicBoolean(false)
    private val ownsNative = AtomicBoolean(false)
    private val bridge = SocksDnsServer(handler)
    private val packetFd = FileDescriptor()
    private val stackFd = FileDescriptor()
    private var nativeThread: Thread? = null
    private var outputThread: Thread? = null

    fun start() {
        check(!stopping.get()) { "TCP adapter is closed" }
        check(nativeOwner.compareAndSet(false, true)) { "A native TCP stack is already active" }
        ownsNative.set(true)
        try {
            bridge.start()
            Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM or OsConstants.O_NONBLOCK, 0, packetFd, stackFd)
            // The external descriptor belongs to this adapter, not to Hev.
            val fd = ParcelFileDescriptor.dup(stackFd)
            Os.close(stackFd)
            val config = """
                tunnel:
                  mtu: 1500
                  ipv4: '${DnsVpnAddresses.IPV4_CLIENT}'
                  ipv6: '${DnsVpnAddresses.IPV6_CLIENT}'
                socks5:
                  address: 127.0.0.1
                  port: ${bridge.port}
                  username: '${bridge.username}'
                  password: '${bridge.password}'
                misc:
                  # Hev evicts at count >= limit; 33 retains 32 active sessions.
                  max-session-count: 33
                  tcp-buffer-size: 16384
                  connect-timeout: 6000
                  tcp-read-write-timeout: 10000
                  log-level: error
            """.trimIndent()
            nativeThread = Thread({
                try {
                    val result = NativeDnsTcp.run(config, fd.fd)
                    if (!stopping.get()) {
                        android.util.Log.e("DnsTcp", "Native TCP stack exited: $result")
                        onFailure()
                    }
                } catch (exception: Throwable) {
                    if (!stopping.get()) {
                        android.util.Log.e("DnsTcp", "Native TCP stack failed", exception)
                        onFailure()
                    }
                } finally { fd.close() }
            }, "dns-tcp-stack").apply { start() }
            outputThread = Thread({
                val packet = ByteArray(1500)
                val poll = StructPollfd().apply { this.fd = packetFd; events = OsConstants.POLLIN.toShort() }
                try {
                    while (!stopping.get()) {
                        Os.poll(arrayOf(poll), -1)
                        if (stopping.get()) break
                        val count = Os.read(packetFd, packet, 0, packet.size)
                        if (count <= 0) break
                        sendPacket(packet.copyOf(count))
                    }
                } catch (exception: Exception) {
                    if (!stopping.get()) {
                        android.util.Log.e("DnsTcp", "Native TCP output failed", exception)
                        onFailure()
                    }
                }
            }, "dns-tcp-output").apply { start() }
        } catch (exception: Exception) {
            // Caller owns close(), including partial startup. Do not join while
            // the service publication lock is held.
            requestStop()
            throw exception
        }
    }

    /** A full queue drops a TCP packet; TCP retransmission handles backpressure. Never block UDP. */
    fun offer(packet: ByteArray, length: Int): Boolean {
        if (!isDnsTcpPacket(packet, length)) return false
        if (stopping.get()) return true
        try {
            Os.write(packetFd, packet, 0, length)
        } catch (exception: ErrnoException) {
            if (exception.errno != OsConstants.EAGAIN && !stopping.get()) throw IOException(exception)
        }
        return true
    }

    fun requestStop() {
        if (!stopping.compareAndSet(false, true)) return
        bridge.close()
        if (nativeThread != null) NativeDnsTcp.stop()
        if (packetFd.valid()) runCatching { Os.shutdown(packetFd, OsConstants.SHUT_RDWR) }
    }

    override fun close() {
        requestStop()
        nativeThread?.join(10_000)
        outputThread?.join(10_000)
        if (packetFd.valid()) Os.close(packetFd)
        if (stackFd.valid()) Os.close(stackFd)
        check(nativeThread?.isAlive != true && outputThread?.isAlive != true) {
            "TCP stack did not stop; refusing to start a second native instance"
        }
        if (ownsNative.compareAndSet(true, false)) nativeOwner.set(false)
    }

    private companion object {
        // Hev owns process-wide state. A failed stop must keep the next start fenced out.
        val nativeOwner = AtomicBoolean(false)
    }
}

private val IPV4_DNS_BYTES = InetAddress.getByName(DnsVpnAddresses.IPV4_DNS).address
private val IPV6_DNS_BYTES = InetAddress.getByName(DnsVpnAddresses.IPV6_DNS).address

internal fun isDnsTcpPacket(packet: ByteArray, readLength: Int): Boolean {
    if (readLength !in 40..1500 || readLength > packet.size) return false
    return when (packet[0].toInt() ushr 4 and 15) {
        4 -> isDnsIpv4TcpPacket(packet, readLength)
        6 -> isDnsIpv6TcpPacket(packet, readLength)
        else -> false
    }
}

private fun isDnsIpv4TcpPacket(packet: ByteArray, readLength: Int): Boolean {
    val headerLength = (packet[0].toInt() and 15) * 4
    if (headerLength < 20 || headerLength > readLength - 20 || readU16(packet, 2) != readLength ||
        readU16(packet, 6) and 0xbfff != 0 || packet[9].toInt() and 255 != 6 ||
        !matchesAt(packet, 16, IPV4_DNS_BYTES)
    ) return false
    return isDnsTcpHeader(packet, headerLength, readLength)
}

private fun isDnsIpv6TcpPacket(packet: ByteArray, readLength: Int): Boolean {
    if (!matchesAt(packet, 24, IPV6_DNS_BYTES)) return false
    val parsed = Ipv6TransportHeaderParser.parse(packet, readLength)
    return parsed is Ipv6TransportHeaderParseResult.Transport && parsed.protocol == 6 &&
        isDnsTcpHeader(packet, parsed.offset, parsed.totalLength)
}

private fun isDnsTcpHeader(packet: ByteArray, offset: Int, readLength: Int): Boolean {
    if (offset > readLength - 20) return false
    val tcpHeaderLength = (packet[offset + 12].toInt() ushr 4 and 15) * 4
    return readU16(packet, offset) != 0 && readU16(packet, offset + 2) == DNS_PORT &&
        tcpHeaderLength >= 20 && tcpHeaderLength <= readLength - offset
}

private fun readU16(packet: ByteArray, offset: Int): Int =
    ((packet[offset].toInt() and 255) shl 8) or (packet[offset + 1].toInt() and 255)

private fun matchesAt(packet: ByteArray, offset: Int, expected: ByteArray): Boolean {
    if (expected.size > packet.size - offset) return false
    for (index in expected.indices) if (packet[offset + index] != expected[index]) return false
    return true
}

private const val DNS_PORT = 53
