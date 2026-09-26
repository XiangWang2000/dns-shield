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
    handlePacket: (ByteArray, Int, T) -> Unit,
    onEnded: (String?) -> Unit
) {
    var failure: String? = null
    var reportTunnelEnded = true
    try {
        val inputStream = openInput()
        try {
            val outputStream = openOutput()
            try {
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
                outputStream.close()
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

internal suspend fun closeVpnTunnelThenJoin(
    closeDescriptor: () -> Unit,
    joinSession: suspend () -> Unit,
    onCloseFailure: (Exception) -> Unit,
    onJoinFailure: (Exception) -> Unit
) {
    try {
        closeDescriptor()
    } catch (exception: Exception) {
        onCloseFailure(exception)
    }

    try {
        joinSession()
    } catch (exception: CancellationException) {
        throw exception
    } catch (exception: Exception) {
        onJoinFailure(exception)
    }
}
