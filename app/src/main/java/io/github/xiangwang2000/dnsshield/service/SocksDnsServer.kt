package io.github.xiangwang2000.dnsshield.service

import java.io.DataInputStream
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.Semaphore
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Authenticated loopback SOCKS5 endpoint for native TCP DNS clients.
 * Each connection can send multiple length-prefixed DNS messages.
 */
internal class SocksDnsServer(
    private val handler: (ByteArray, (ByteArray) -> Unit) -> Unit,
    private val maxSessions: Int = 32,
    private val idleTimeoutMillis: Int = 10_000
) : AutoCloseable {
    val username: String = randomHexCredential()
    val password: String = randomHexCredential()

    private val stopped = AtomicBoolean(false)
    private val sessionSlots = Semaphore(maxSessions)
    private val sessions = ConcurrentHashMap.newKeySet<Session>()
    private val workers = ThreadPoolExecutor(
        maxSessions,
        maxSessions,
        0L,
        TimeUnit.MILLISECONDS,
        ArrayBlockingQueue(maxSessions),
        daemonThreadFactory("socks-dns-worker"),
        ThreadPoolExecutor.AbortPolicy()
    )
    private val watchdog = ScheduledThreadPoolExecutor(1, daemonThreadFactory("socks-dns-watchdog")).apply {
        removeOnCancelPolicy = true
    }
    private val lifecycleLock = Any()

    @Volatile
    private var listener: ServerSocket? = null

    @Volatile
    private var boundPort: Int? = null

    val port: Int
        get() = checkNotNull(boundPort) { "SocksDnsServer has not been started" }

    init {
        require(maxSessions > 0) { "maxSessions must be positive" }
        require(idleTimeoutMillis > 0) { "idleTimeoutMillis must be positive" }
    }

    fun start() {
        synchronized(lifecycleLock) {
            check(!stopped.get()) { "SocksDnsServer is closed" }
            check(listener == null) { "SocksDnsServer has already been started" }
            val server = ServerSocket()
            try {
                server.bind(InetSocketAddress(LOOPBACK, 0), maxSessions)
                listener = server
                boundPort = server.localPort
                daemonThreadFactory("socks-dns-accept").newThread { acceptLoop(server) }.start()
            } catch (failure: Throwable) {
                closeQuietly(server)
                listener = null
                boundPort = null
                throw failure
            }
        }
    }

    override fun close() {
        synchronized(lifecycleLock) {
            if (!stopped.compareAndSet(false, true)) return
            listener?.let(::closeQuietly)
            sessions.toList().forEach(Session::close)
            watchdog.shutdownNow()
            workers.shutdownNow()
        }
    }

    private fun acceptLoop(server: ServerSocket) {
        while (!stopped.get()) {
            val socket = try {
                server.accept()
            } catch (failure: IOException) {
                if (stopped.get()) return
                throw failure
            }
            if (stopped.get()) {
                closeQuietly(socket)
                return
            }
            if (!sessionSlots.tryAcquire()) {
                closeQuietly(socket)
                continue
            }

            val session = Session(socket)
            sessions.add(session)
            if (stopped.get()) {
                session.close()
                return
            }
            try {
                workers.execute(session)
            } catch (failure: RejectedExecutionException) {
                session.close()
                if (!stopped.get()) throw failure
            }
        }
    }

    private inner class Session(private val socket: Socket) : Runnable {
        private val finished = AtomicBoolean(false)

        override fun run() {
            if (finished.get()) return
            try {
                serve()
            } finally {
                finish()
            }
        }

        fun close() = finish()

        private fun serve() {
            try {
                socket.soTimeout = idleTimeoutMillis
            } catch (failure: IOException) {
                if (stopped.get() || socket.isClosed) return
                throw failure
            }

            val input: DataInputStream
            val output: OutputStream
            try {
                input = DataInputStream(socket.getInputStream())
                output = socket.getOutputStream()
            } catch (failure: IOException) {
                if (stopped.get() || socket.isClosed) return
                throw failure
            }

            val handshakeWatchdog = scheduleSocketClose(socket) ?: return
            val authenticated = try {
                try {
                    negotiate(input, output)
                } catch (_: IOException) {
                    false
                }
            } finally {
                handshakeWatchdog.cancel(false)
            }
            if (!authenticated) return

            while (!stopped.get() && !socket.isClosed) {
                val frameWatchdog = scheduleSocketClose(socket) ?: return
                val query = try {
                    try {
                        DnsTcpFrameCodec.readFrame(input)
                    } catch (_: IOException) {
                        return
                    }
                } finally {
                    frameWatchdog.cancel(false)
                } ?: return

                val requestWatchdog = scheduleSocketClose(socket) ?: return
                val responseSent = AtomicBoolean(false)
                val peerWriteFailure = AtomicReference<IOException?>()
                try {
                    handler(query) { response ->
                        if (responseSent.compareAndSet(false, true)) {
                            try {
                                DnsTcpFrameCodec.writeFrame(output, response)
                            } catch (failure: IOException) {
                                peerWriteFailure.set(failure)
                                closeQuietly(socket)
                            }
                        }
                    }
                } finally {
                    requestWatchdog.cancel(false)
                }
                if (peerWriteFailure.get() != null || !responseSent.get()) return
            }
        }

        private fun finish() {
            if (finished.compareAndSet(false, true)) {
                closeQuietly(socket)
                sessions.remove(this)
                sessionSlots.release()
            }
        }
    }
    private fun scheduleSocketClose(socket: Socket): ScheduledFuture<*>? = try {
        watchdog.schedule(
            { closeQuietly(socket) },
            idleTimeoutMillis.toLong(),
            TimeUnit.MILLISECONDS
        )
    } catch (failure: RejectedExecutionException) {
        if (stopped.get()) null else throw failure
    }

    private fun negotiate(input: DataInputStream, output: OutputStream): Boolean {
        val version = input.read()
        val methodCount = input.read()
        if (version != SOCKS_VERSION || methodCount < 0) {
            writeQuietly(output, byteArrayOf(SOCKS_VERSION.toByte(), NO_ACCEPTABLE_METHOD.toByte()))
            return false
        }
        val methods = ByteArray(methodCount)
        input.readFully(methods)
        if (methods.none { (it.toInt() and 0xFF) == METHOD_USER_PASSWORD }) {
            writeQuietly(output, byteArrayOf(SOCKS_VERSION.toByte(), NO_ACCEPTABLE_METHOD.toByte()))
            return false
        }
        if (!writeQuietly(output, byteArrayOf(SOCKS_VERSION.toByte(), METHOD_USER_PASSWORD.toByte()))) return false

        val authVersion = input.read()
        val usernameLength = input.read()
        if (authVersion < 0 || usernameLength <= 0) {
            writeQuietly(output, byteArrayOf(AUTH_VERSION.toByte(), AUTH_FAILURE.toByte()))
            return false
        }
        val suppliedUsername = ByteArray(usernameLength)
        input.readFully(suppliedUsername)
        val passwordLength = input.read()
        if (passwordLength <= 0) {
            writeQuietly(output, byteArrayOf(AUTH_VERSION.toByte(), AUTH_FAILURE.toByte()))
            return false
        }
        val suppliedPassword = ByteArray(passwordLength)
        input.readFully(suppliedPassword)

        val usernameMatches = constantTimeEquals(username.toByteArray(Charsets.UTF_8), suppliedUsername)
        val passwordMatches = constantTimeEquals(password.toByteArray(Charsets.UTF_8), suppliedPassword)
        val valid = authVersion == AUTH_VERSION && usernameMatches && passwordMatches
        if (!writeQuietly(output, byteArrayOf(AUTH_VERSION.toByte(), if (valid) 0.toByte() else AUTH_FAILURE.toByte()))) {
            return false
        }
        if (!valid) return false

        val request = ByteArray(4)
        input.readFully(request)
        if ((request[0].toInt() and 0xFF) != SOCKS_VERSION || request[2].toInt() != 0) {
            writeReply(output, REP_GENERAL_FAILURE)
            return false
        }
        if ((request[1].toInt() and 0xFF) != CMD_CONNECT) {
            writeReply(output, REP_COMMAND_NOT_SUPPORTED)
            return false
        }
        if ((request[3].toInt() and 0xFF) != ATYP_IPV4) {
            writeReply(output, REP_ADDRESS_NOT_SUPPORTED)
            return false
        }

        val address = ByteArray(4)
        input.readFully(address)
        val destinationPort = (input.read() shl 8) or input.read()
        if (!address.contentEquals(DNS_IPV4) || destinationPort != DNS_PORT) {
            writeReply(output, REP_NOT_ALLOWED)
            return false
        }
        return writeReply(output, REP_SUCCEEDED)
    }

    private fun writeReply(output: OutputStream, status: Int): Boolean =
        writeQuietly(
            output,
            byteArrayOf(SOCKS_VERSION.toByte(), status.toByte(), 0, ATYP_IPV4.toByte(), 0, 0, 0, 0, 0, 0)
        )

    private fun writeQuietly(output: OutputStream, bytes: ByteArray): Boolean = try {
        output.write(bytes)
        output.flush()
        true
    } catch (_: IOException) {
        false
    }

    private fun constantTimeEquals(expected: ByteArray, actual: ByteArray): Boolean {
        var difference = expected.size xor actual.size
        expected.indices.forEach { index ->
            val supplied = if (index < actual.size) actual[index].toInt() else 0
            difference = difference or (expected[index].toInt() xor supplied)
        }
        return difference == 0
    }

    private fun closeQuietly(socket: Socket) {
        try {
            socket.shutdownInput()
        } catch (_: IOException) {
        }
        try {
            socket.shutdownOutput()
        } catch (_: IOException) {
        }
        try {
            socket.close()
        } catch (_: IOException) {
        }
    }

    private fun closeQuietly(server: ServerSocket) {
        try {
            server.close()
        } catch (_: IOException) {
        }
    }

    private fun daemonThreadFactory(prefix: String): ThreadFactory {
        val sequence = AtomicInteger()
        return ThreadFactory { task ->
            Thread(task, prefix + "-" + sequence.incrementAndGet()).apply { isDaemon = true }
        }
    }

    private fun randomHexCredential(): String {
        val bytes = ByteArray(CREDENTIAL_BYTES).also(SECURE_RANDOM::nextBytes)
        val chars = CharArray(bytes.size * 2)
        bytes.forEachIndexed { index, byte ->
            val value = byte.toInt() and 0xFF
            chars[index * 2] = HEX[value ushr 4]
            chars[index * 2 + 1] = HEX[value and 0x0F]
        }
        return String(chars)
    }

    private companion object {
        const val SOCKS_VERSION = 5
        const val AUTH_VERSION = 1
        const val METHOD_USER_PASSWORD = 2
        const val NO_ACCEPTABLE_METHOD = 0xFF
        const val AUTH_FAILURE = 1
        const val CMD_CONNECT = 1
        const val ATYP_IPV4 = 1
        const val REP_SUCCEEDED = 0
        const val REP_GENERAL_FAILURE = 1
        const val REP_NOT_ALLOWED = 2
        const val REP_COMMAND_NOT_SUPPORTED = 7
        const val REP_ADDRESS_NOT_SUPPORTED = 8
        const val DNS_PORT = 53
        const val CREDENTIAL_BYTES = 24
        const val HEX = "0123456789abcdef"
        val DNS_IPV4 = byteArrayOf(10, 0, 0, 1)
        val LOOPBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val SECURE_RANDOM = SecureRandom()
    }
}
