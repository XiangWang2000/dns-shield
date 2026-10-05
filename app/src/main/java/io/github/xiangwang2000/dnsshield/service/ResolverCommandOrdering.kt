package io.github.xiangwang2000.dnsshield.service

import io.github.xiangwang2000.dnsshield.data.DnsServer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch

/** Process-local ordering for resolver changes. The counter is deliberately not persisted. */
class ResolverCommandRevisionClock {
    private val lock = Any()
    private var highWater = 0L

    fun next(): Long = synchronized(lock) {
        check(highWater < Long.MAX_VALUE) { "Resolver command revision exhausted" }
        ++highWater
    }

    /** Legacy commands get a fresh token; observed tokens advance, but never lower, the clock. */
    fun receive(revision: Long?): Long = synchronized(lock) {
        if (revision == null || revision <= 0L) {
            check(highWater < Long.MAX_VALUE) { "Resolver command revision exhausted" }
            ++highWater
        } else {
            highWater = maxOf(highWater, revision)
            revision
        }
    }

    fun isCurrent(revision: Long): Boolean = synchronized(lock) { highWater == revision }

    fun <T : Any> applyIfCurrent(revision: Long, action: () -> T): T? = synchronized(lock) {
        if (highWater == revision) action() else null
    }
}

data class ResolverCommandSubmission<T>(
    val revision: Long,
    val result: Deferred<T>
)

object ResolverCommandRuntime {
    private val commandScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val revisions = ResolverCommandRevisionClock()
    val coordinator = ResolverCommandCoordinator(revisions, commandScope)
    val serviceFence = ResolverCommandRevisionFence(revisions)
}

data class ResolverUpdateCommand(
    val requestedResolverId: Int,
    val revision: Long
)

/** A process-scoped FIFO: submission order is fixed before callers launch asynchronous work. */
class ResolverCommandCoordinator(
    private val revisions: ResolverCommandRevisionClock,
    scope: CoroutineScope
) {
    private interface QueuedCommand {
        suspend fun execute()
    }

    private class QueuedCommandImpl<T>(
        private val action: suspend () -> T
    ) : QueuedCommand {
        val result = CompletableDeferred<T>()

        override suspend fun execute() {
            try {
                result.complete(action())
            } catch (exception: CancellationException) {
                result.completeExceptionally(exception)
            } catch (exception: Exception) {
                result.completeExceptionally(exception)
            }
        }
    }

    private val submissionLock = Any()
    private val commands = Channel<QueuedCommand>(Channel.UNLIMITED)
    private val latestFallbackRevisionByResolver = mutableMapOf<Int, Long>()
    private val worker = scope.launch(Dispatchers.IO) {
        for (command in commands) command.execute()
    }

    fun <T> submit(action: suspend (Long) -> T): ResolverCommandSubmission<T> =
        synchronized(submissionLock) {
            val revision = revisions.next()
            enqueueLocked(revision) { action(revision) }
        }

    /** Records an incoming intent and its queue position atomically; null is a legacy command. */
    fun <T> submitReceived(
        requestedRevision: Long?,
        action: suspend (Long) -> T
    ): ResolverCommandSubmission<T> = synchronized(submissionLock) {
        val revision = revisions.receive(requestedRevision)
        enqueueLocked(revision) { action(revision) }
    }

    /** The same-server latest policy token only controls the immediate runtime fence. */
    fun <T> submitFallbackPolicy(
        resolverId: Int,
        onSubmitted: () -> Unit = {},
        action: suspend (Long, applyRuntimeFence: (() -> Unit) -> Boolean) -> T
    ): ResolverCommandSubmission<T> = synchronized(submissionLock) {
        val revision = revisions.next()
        latestFallbackRevisionByResolver[resolverId] = revision
        onSubmitted()
        enqueueLocked(revision) {
            action(revision) { applyFence ->
                val current = synchronized(submissionLock) {
                    latestFallbackRevisionByResolver[resolverId] == revision
                }
                if (current) applyFence()
                current
            }
        }
    }

    fun dispatchIfCurrent(
        revision: Long,
        active: DnsServer?,
        dispatch: (DnsServer, Long) -> Unit
    ): Boolean {
        if (active == null) return false
        return revisions.applyIfCurrent(revision) {
            dispatch(active, revision)
            true
        } == true
    }

    /** Tests close their worker after awaiting submissions; production lives for the process. */
    suspend fun closeAndJoin() {
        commands.close()
        worker.join()
    }

    private fun <T> enqueueLocked(
        revision: Long,
        action: suspend () -> T
    ): ResolverCommandSubmission<T> {
        val command = QueuedCommandImpl(action)
        val sent = commands.trySend(command)
        if (sent.isFailure) {
            command.result.completeExceptionally(
                sent.exceptionOrNull() ?: IllegalStateException("Resolver command queue is closed")
            )
        }
        return ResolverCommandSubmission(revision, command.result)
    }
}

/** Re-reads the active DB row and atomically fences application against a newer command. */
class ResolverCommandRevisionFence(private val revisions: ResolverCommandRevisionClock) {
    suspend fun applyLatestActive(
        command: ResolverUpdateCommand,
        readActive: suspend () -> DnsServer?,
        apply: (DnsServer) -> Unit
    ): Boolean? {
        if (!revisions.isCurrent(command.revision)) return null
        val active = readActive()
        return revisions.applyIfCurrent(command.revision) {
            if (active == null) false else {
                apply(active)
                true
            }
        }
    }
}
