package io.github.xiangwang2000.dnsshield.service

import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyAssembler
import io.github.xiangwang2000.dnsshield.blocking.ReloadableDomainPolicy
import io.github.xiangwang2000.dnsshield.blocking.UserDomainRule
import io.github.xiangwang2000.dnsshield.blocking.DomainRuleAction
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DnsResolvedResponseCommitterTest {
    @Test
    fun allowReloadBeforeCommitRejectsPreviouslyComputedBlockedNxDomain() {
        val query = DnsTestMessages.query()
        val parsed = (DnsMessageValidator.parseQuery(query) as DnsQueryParseResult.Valid).query
        val domain = requireNotNull(parsed.question.domainName)
        val blocked = DomainPolicyAssembler.assemble(
            userRules = listOf(UserDomainRule(domain, DomainRuleAction.BLOCK, false))
        )
        val allowed = DomainPolicyAssembler.assemble(
            userRules = listOf(UserDomainRule(domain, DomainRuleAction.ALLOW, false))
        )
        val policy = ReloadableDomainPolicy(blocked)
        val stateLock = Any()
        val computed = CountDownLatch(1)
        val releaseCommit = CountDownLatch(1)
        val accepted = AtomicReference<Boolean?>()
        val delivered = AtomicReference<ByteArray?>()
        val sender = thread {
            val snapshot = policy.snapshot()
            if (!snapshot.matcher.shouldBlock(domain)) return@thread
            val response = DnsMessageValidator.buildNxDomainResponse(parsed)
            computed.countDown()
            if (!releaseCommit.await(2, TimeUnit.SECONDS)) return@thread
            accepted.set(DnsResolvedResponseCommitter.sendIfCurrent(
                stateLock = stateLock,
                isCurrent = { policy.snapshot() === snapshot },
                response = response,
                transactionIdSource = query,
                responseWriter = DnsResponseWriter { delivered.set(it) }
            ))
        }
        try {
            assertTrue(computed.await(1, TimeUnit.SECONDS))
            synchronized(stateLock) { policy.install(allowed) }
            assertFalse(policy.shouldBlock(domain))
            releaseCommit.countDown()
            sender.join(2_000)
            assertFalse(sender.isAlive)
            assertEquals(false, accepted.get())
            assertEquals(null, delivered.get(), "Old BLOCK must not commit NXDOMAIN after ALLOW reload")
        } finally {
            releaseCommit.countDown()
            sender.join(2_000)
        }
    }

    @Test
    fun slowTunWriteDoesNotHoldResolverStateLock() {
        val stateLock = Any()
        var generation = 1
        val queryGeneration = generation
        val writing = CountDownLatch(1)
        val releaseWrite = CountDownLatch(1)
        val updated = CountDownLatch(1)
        val sender = thread {
            DnsResolvedResponseCommitter.sendIfCurrent(
                stateLock, { generation == queryGeneration }, byteArrayOf(1, 2, 3), byteArrayOf(4, 5),
                DnsResponseWriter {
                    writing.countDown()
                    releaseWrite.await(2, TimeUnit.SECONDS)
                }
            )
        }
        var updater: Thread? = null
        try {
            assertTrue(writing.await(1, TimeUnit.SECONDS), "response writer did not start")
            updater = thread {
                synchronized(stateLock) {
                    generation++
                    updated.countDown()
                }
            }
            assertTrue(updated.await(1, TimeUnit.SECONDS), "resolver update waited for TUN write")
            var staleResponseSent = false
            assertFalse(DnsResolvedResponseCommitter.sendIfCurrent(
                stateLock, { generation == queryGeneration }, byteArrayOf(1, 2, 3), byteArrayOf(4, 5),
                DnsResponseWriter { staleResponseSent = true }
            ))
            assertFalse(staleResponseSent)
        } finally {
            releaseWrite.countDown()
            sender.join(2_000)
            updater?.join(2_000)
        }
        assertFalse(sender.isAlive)
        assertFalse(updater.isAlive)
    }

    @Test
    fun resolverOrStrictModeChangeBeforeCommitRejectsOldResponse() {
        val stateLock = Any()
        var generation = 1
        val oldGeneration = generation
        synchronized(stateLock) { generation++ }
        var sent = false
        val accepted = DnsResolvedResponseCommitter.sendIfCurrent(
            stateLock, { generation == oldGeneration }, byteArrayOf(1, 2, 3), byteArrayOf(4, 5),
            DnsResponseWriter { sent = true }
        )
        assertFalse(accepted)
        assertFalse(sent)
    }

    @Test
    fun committedResponseKeepsOriginalBytesAndUsesClientTransactionId() {
        val original = byteArrayOf(1, 2, 3)
        var delivered: ByteArray? = null
        assertTrue(DnsResolvedResponseCommitter.sendIfCurrent(
            Any(), { true }, original, byteArrayOf(4, 5), DnsResponseWriter { delivered = it }
        ))
        assertContentEquals(byteArrayOf(4, 5, 3), delivered)
        assertContentEquals(byteArrayOf(1, 2, 3), original)
    }
}
