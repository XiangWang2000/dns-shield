package io.github.xiangwang2000.dnsshield.service

import java.io.DataInputStream
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SocksDnsServerTest {
    @Test
    fun requiresUsernamePasswordAndRejectsBadCredentials() {
        withServer { server ->
            connect(server).use { socket ->
                socket.getOutputStream().write(byteArrayOf(5, 1, 0))
                socket.getOutputStream().flush()
                assertContentEquals(byteArrayOf(5, 0xFF.toByte()), readBytes(socket, 2))
            }

            connect(server).use { socket ->
                assertEquals(1, authenticate(socket, "wrong", server.password))
                awaitClosed(socket)
            }
            connect(server).use { socket ->
                assertEquals(1, authenticate(socket, server.username, "wrong"))
                awaitClosed(socket)
            }
        }
    }

    @Test
    fun onlyAcceptsConnectToIpv4DnsEndpoint() {
        withServer { server ->
            assertEquals(2, requestStatus(server, 1, 1, byteArrayOf(1, 1, 1, 1, 0, 53)))
            assertEquals(2, requestStatus(server, 1, 1, byteArrayOf(10, 0, 0, 1, 0, 54)))
            assertEquals(
                8,
                requestStatus(server, 1, 3, byteArrayOf(3) + "dns".toByteArray() + byteArrayOf(0, 53))
            )
            assertEquals(7, requestStatus(server, 3, 1, byteArrayOf(10, 0, 0, 1, 0, 53)))
        }
    }

    @Test
    fun handlesMultipleFramesAndCallbackOnAnotherThread() {
        withServer(
            handler = { query, respond ->
                val callback = Thread({ respond(query.reversedArray()) }, "socks-test-callback").apply {
                    isDaemon = true
                    start()
                }
                callback.join(1_000)
            }
        ) { server ->
            connect(server).use { socket ->
                assertEquals(0, requestStatus(socket, server, 1, 1, byteArrayOf(10, 0, 0, 1, 0, 53)))
                val first = byteArrayOf(1, 2, 3)
                val second = byteArrayOf(8, 7)
                DnsTcpFrameCodec.writeFrame(socket.getOutputStream(), first)
                DnsTcpFrameCodec.writeFrame(socket.getOutputStream(), second)
                assertContentEquals(first.reversedArray(), DnsTcpFrameCodec.readFrame(socket.getInputStream()))
                assertContentEquals(second.reversedArray(), DnsTcpFrameCodec.readFrame(socket.getInputStream()))
            }
        }
    }

    @Test
    fun drainsResponseAfterClientHalfCloses() {
        withServer { server ->
            connect(server).use { socket ->
                assertEquals(0, requestStatus(socket, server, 1, 1, byteArrayOf(10, 0, 0, 1, 0, 53)))
                val query = byteArrayOf(1, 9, 4)
                DnsTcpFrameCodec.writeFrame(socket.getOutputStream(), query)
                socket.shutdownOutput()
                assertContentEquals(query, DnsTcpFrameCodec.readFrame(socket.getInputStream()))
                assertNull(DnsTcpFrameCodec.readFrame(socket.getInputStream()))
            }
        }
    }

    @Test
    fun rejectsConnectionsAboveSessionCapacity() {
        withServer(maxSessions = 1, idleTimeoutMillis = 5_000) { server ->
            connect(server).use { first ->
                assertEquals(0, requestStatus(first, server, 1, 1, byteArrayOf(10, 0, 0, 1, 0, 53)))
                try { connect(server).use { second -> awaitClosed(second) } }
                catch (_: ConnectException) { /* The OS may reject a full listener before accept. */ }
                val query = byteArrayOf(1, 2, 3)
                DnsTcpFrameCodec.writeFrame(first.getOutputStream(), query)
                assertContentEquals(query, DnsTcpFrameCodec.readFrame(first.getInputStream()))
            }
        }
    }

    @Test
    fun closesIdleAndMalformedFrameSessions() {
        withServer(idleTimeoutMillis = 150) { server ->
            connect(server).use { socket ->
                assertEquals(0, requestStatus(socket, server, 1, 1, byteArrayOf(10, 0, 0, 1, 0, 53)))
                awaitClosed(socket)
            }
        }

        withServer { server ->
            connect(server).use { socket ->
                assertEquals(0, requestStatus(socket, server, 1, 1, byteArrayOf(10, 0, 0, 1, 0, 53)))
                socket.getOutputStream().write(byteArrayOf(0, 0))
                socket.getOutputStream().flush()
                awaitClosed(socket)
            }
        }
    }

    @Test
    fun closeUnblocksPendingHandshakeAndStopsListenerWithoutWaiting() {
        val server = SocksDnsServer(handler = { _, _ -> }, idleTimeoutMillis = 10_000)
        server.start()
        val port = server.port
        connect(server).use { socket ->
            socket.getOutputStream().write(byteArrayOf(5, 1, 2))
            socket.getOutputStream().flush()
            assertContentEquals(byteArrayOf(5, 2), readBytes(socket, 2))
            val username = server.username.toByteArray(Charsets.UTF_8)
            socket.getOutputStream().write(byteArrayOf(1, username.size.toByte(), username[0]))
            socket.getOutputStream().flush()

            val started = System.nanoTime()
            server.close()
            val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue(elapsedMillis < 1_000, "close took " + elapsedMillis + "ms")
            awaitClosed(socket)
        }

        Socket().use { refused ->
            assertFailsWith<ConnectException> {
                refused.connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 500)
            }
        }
    }

    private fun requestStatus(
        server: SocksDnsServer,
        command: Int,
        addressType: Int,
        payload: ByteArray
    ): Int = connect(server).use { socket ->
        requestStatus(socket, server, command, addressType, payload)
    }

    private fun requestStatus(
        socket: Socket,
        server: SocksDnsServer,
        command: Int,
        addressType: Int,
        payload: ByteArray
    ): Int {
        assertEquals(0, authenticate(socket, server.username, server.password))
        socket.getOutputStream().write(byteArrayOf(5, command.toByte(), 0, addressType.toByte()) + payload)
        socket.getOutputStream().flush()
        val reply = readBytes(socket, 10)
        assertEquals(5, reply[0].toInt() and 0xFF)
        return reply[1].toInt() and 0xFF
    }

    private fun authenticate(socket: Socket, username: String, password: String): Int {
        val output = socket.getOutputStream()
        output.write(byteArrayOf(5, 1, 2))
        output.flush()
        assertContentEquals(byteArrayOf(5, 2), readBytes(socket, 2))

        val user = username.toByteArray(Charsets.UTF_8)
        val pass = password.toByteArray(Charsets.UTF_8)
        output.write(byteArrayOf(1, user.size.toByte()))
        output.write(user)
        output.write(pass.size)
        output.write(pass)
        output.flush()

        val reply = readBytes(socket, 2)
        assertEquals(1, reply[0].toInt() and 0xFF)
        return reply[1].toInt() and 0xFF
    }

    private fun readBytes(socket: Socket, count: Int): ByteArray =
        ByteArray(count).also { DataInputStream(socket.getInputStream()).readFully(it) }

    private fun awaitClosed(socket: Socket) {
        try {
            assertEquals(-1, socket.getInputStream().read())
        } catch (_: SocketException) {
            // A peer reset also proves the session socket was closed.
        }
    }

    private fun connect(server: SocksDnsServer): Socket =
        Socket().apply {
            soTimeout = 2_000
            connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), server.port), 1_000)
        }

    private fun withServer(
        handler: (ByteArray, (ByteArray) -> Unit) -> Unit = { query, respond -> respond(query) },
        maxSessions: Int = 32,
        idleTimeoutMillis: Int = 1_000,
        block: (SocksDnsServer) -> Unit
    ) {
        SocksDnsServer(handler, maxSessions, idleTimeoutMillis).use { server ->
            server.start()
            block(server)
        }
    }
}
