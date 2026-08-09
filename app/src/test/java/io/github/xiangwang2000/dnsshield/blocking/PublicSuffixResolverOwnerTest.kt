package io.github.xiangwang2000.dnsshield.blocking

import java.nio.ByteBuffer
import java.util.Base64
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame

class PublicSuffixResolverOwnerTest {
    @Test
    fun successfulLoadIsOwnedOnceAndReused() {
        val loads = AtomicInteger()
        val resolver = fixtureResolver()
        val owner = PublicSuffixResolverOwner {
            loads.incrementAndGet()
            resolver
        }

        assertEquals(PublicSuffixResolverStatus.NotLoaded, owner.status())

        val first = owner.resolverOrNull()
        val second = owner.resolverOrNull()

        assertSame(resolver, first)
        assertSame(first, second)
        assertEquals(1, loads.get())
        assertEquals(
            PublicSuffixResolverStatus.Loaded(
                exactRules = 9,
                wildcardRules = 2,
                exceptionRules = 2
            ),
            owner.status()
        )
    }

    @Test
    fun concurrentCallersShareOneLifecycleLoad() {
        val loads = AtomicInteger()
        val resolver = fixtureResolver()
        val owner = PublicSuffixResolverOwner {
            loads.incrementAndGet()
            Thread.sleep(20)
            resolver
        }
        val executor = Executors.newFixedThreadPool(8)

        try {
            val futures = executor.invokeAll(
                List(16) { Callable { owner.resolverOrNull() } }
            )
            val results = futures.map { it.get(5, TimeUnit.SECONDS) }

            assertEquals(1, loads.get())
            results.forEach { result -> assertSame(resolver, result) }
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun failedLoadIsTerminalForOwnerInstance() {
        val loads = AtomicInteger()
        val owner = PublicSuffixResolverOwner {
            loads.incrementAndGet()
            throw IllegalArgumentException("corrupt production asset")
        }

        assertNull(owner.resolverOrNull())
        assertNull(owner.resolverOrNull())
        assertEquals(1, loads.get())

        val status = assertIs<PublicSuffixResolverStatus.Rejected>(owner.status())
        assertEquals("corrupt production asset", status.reason)
    }

    @Test
    fun failedLoadFallsBackToExceptionTypeWhenMessageIsBlank() {
        val owner = PublicSuffixResolverOwner {
            throw IllegalStateException("")
        }

        assertNull(owner.resolverOrNull())
        val status = assertIs<PublicSuffixResolverStatus.Rejected>(owner.status())
        assertEquals("IllegalStateException", status.reason)
    }

    private fun fixtureResolver(): CompiledPublicSuffixList =
        CompiledPublicSuffixList.fromByteBuffer(ByteBuffer.wrap(fixtureArtifact))

    private val fixtureArtifact: ByteArray
        get() = Base64.getDecoder().decode(
            "RE5TSFBTMDEBAAAAAQAAAAkAAAACAAAAAgAAAHPsytv9BqHn5cpMuwAfzbOdZfBHZliCgeL6TGd89acrDABibG9nc3BvdC5jb20CAGNrBQBjby51awMAY29tCQBnaXRodWIuaW8CAGlvAgBqcAMAb3JnAgB1awIAY2sLAGthd2FzYWtpLmpwEABjaXR5Lmthd2FzYWtpLmpwBgB3d3cuY2s="
        )
}
