package io.github.xiangwang2000.dnsshield.service

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import kotlinx.coroutines.CancellationException

internal fun <T : Any> establishVpnTunnel(
    establish: () -> T?,
    onUnavailable: () -> Unit
): T? = establish() ?: run {
    onUnavailable()
    null
}

internal fun <T : OutputStream> runVpnTunnelReader(
    openInput: () -> InputStream,
    openOutput: () -> T,
    isActive: () -> Boolean,
    onOutputOpened: (T) -> Unit = {},
    handlePacket: (ByteArray, Int, T) -> Unit,
    onOutputClosing: (T) -> Unit = {},
    onEnded: (String?) -> Unit
) {
    var failure: String? = null
    var reportTunnelEnded = true
    try {
        val inputStream = openInput()
        try {
            val outputStream = openOutput()
            try {
                onOutputOpened(outputStream)
                val buffer = ByteArray(4096)
                while (isActive()) {
                    val readBytes = inputStream.read(buffer)
                    if (readBytes > 0) {
                        handlePacket(buffer, readBytes, outputStream)
                    } else if (readBytes < 0) {
                        if (isActive()) {
                            failure = "Tunnel stream reached EOF unexpectedly"
                        }
                        break
                    }
                }
            } finally {
                try {
                    onOutputClosing(outputStream)
                } finally {
                    outputStream.close()
                }
            }
        } finally {
            inputStream.close()
        }
    } catch (exception: IOException) {
        if (isActive()) {
            failure = "Tunnel read error: " + exception.message
        }
    } catch (exception: CancellationException) {
        reportTunnelEnded = false
        throw exception
    } catch (exception: Exception) {
        if (isActive()) {
            failure = "Tunnel reader failed: " + (exception.message ?: exception.javaClass.simpleName)
        }
    } finally {
        if (reportTunnelEnded) onEnded(failure)
    }
}

/** Owns a single session's interruptible input, including STOP racing with open. */
internal class VpnTunnelInputOwner {
    private val lock = Any()
    private var stopped = false
    private var input: InputStream? = null

    fun open(openInput: () -> InputStream): InputStream {
        synchronized(lock) {
            if (stopped) throw IOException("Tunnel reader already stopped")
        }
        val opened = openInput()
        val accepted = synchronized(lock) {
            if (stopped) false else {
                input = opened
                true
            }
        }
        if (!accepted) {
            opened.close()
            throw IOException("Tunnel reader stopped while opening input")
        }
        return opened
    }

    fun stop() {
        val opened = synchronized(lock) {
            stopped = true
            input.also { input = null }
        }
        // A channel close can wait for its reader; never retain the registration lock.
        opened?.close()
    }
}
