package io.github.xiangwang2000.dnsshield.service

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.Closeable
import java.io.FileDescriptor
import java.io.IOException
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
                  ipv4: 10.0.0.2
                socks5:
                  address: 127.0.0.1
                  port: ${bridge.port}
                  username: '${bridge.username}'
                  password: '${bridge.password}'
                misc:
                  max-session-count: 32
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

internal fun isDnsTcpPacket(packet: ByteArray, length: Int): Boolean {
    if (length !in 40..1500 || length > packet.size || packet[0].toInt() ushr 4 and 15 != 4) return false
    val header = (packet[0].toInt() and 15) * 4
    fun u16(offset: Int) = ((packet[offset].toInt() and 255) shl 8) or (packet[offset + 1].toInt() and 255)
    if (header < 20 || header + 20 > length || u16(2) != length || u16(6) and 0xbfff != 0) return false
    if (packet[9].toInt() and 255 != 6 || !packet.copyOfRange(16, 20).contentEquals(byteArrayOf(10, 0, 0, 1))) return false
    val tcpHeader = (packet[header + 12].toInt() ushr 4 and 15) * 4
    return u16(header) != 0 && u16(header + 2) == 53 && tcpHeader >= 20 && header + tcpHeader <= length
}
