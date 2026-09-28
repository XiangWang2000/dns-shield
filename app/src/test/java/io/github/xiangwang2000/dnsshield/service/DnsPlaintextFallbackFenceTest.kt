package io.github.xiangwang2000.dnsshield.service

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DnsPlaintextFallbackFenceTest {
    @Test
    fun strictSelectionBlocksPendingUdpSend() {
        val resolverId = 41
        val fence = DnsPlaintextFallbackFence()
        val receiver = DatagramSocket(0).apply { soTimeout = 200 }
        val socket = PolicyFencedDatagramSocket(
            resolverId = resolverId,
            snapshotAllowsPlaintext = true,
            fence = fence,
            currentPolicyAllowsPlaintext = { true }
        )
        val sendReady = CountDownLatch(1)
        val continueSend = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        val sender = Thread {
            sendReady.countDown()
            try {
                check(continueSend.await(5, TimeUnit.SECONDS))
                socket.send(
                    DatagramPacket(
                        byteArrayOf(1),
                        1,
                        InetAddress.getByName("127.0.0.1"),
                        receiver.localPort
                    )
                )
            } catch (exception: Throwable) {
                failure.set(exception)
            }
        }

        try {
            sender.start()
            assertTrue(sendReady.await(5, TimeUnit.SECONDS))
            fence.setAllowed(resolverId, false)
            continueSend.countDown()
            sender.join(5_000)

            assertFalse(sender.isAlive)
            assertIs<SocketException>(failure.get())
            assertTrue(
                runCatching {
                    receiver.receive(DatagramPacket(ByteArray(8), 8))
                }.exceptionOrNull() is SocketTimeoutException
            )
        } finally {
            continueSend.countDown()
            socket.close()
            receiver.close()
            sender.join(5_000)
        }
    }
}
