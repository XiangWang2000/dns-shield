package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import androidx.annotation.VisibleForTesting
import io.github.xiangwang2000.dnsshield.BuildConfig
import okhttp3.OkHttpClient
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicLongArray
import java.util.concurrent.atomic.AtomicReference

/**
 * Isolated instrumentation hooks and measurements used by DNS service variants.
 *
 * The process-scoped log and diagnostic data itself remains owned by [DnsLogRuntime].
 */
internal class DnsVpnServiceTestHooks(
    private val plaintextFallbackFence: DnsPlaintextFallbackFence,
    private val closePlaintextFallbackSocketsAsync: (Int, Long) -> Unit,
    private val replaceHttpClient: (OkHttpClient?) -> Unit
) {
    @Volatile
    private var d08StartupBenchmarkIsolation = false

    internal val isolatePackages: Boolean
        get() = BuildConfig.D14_DEVICE_TEST || d08StartupBenchmarkIsolation

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun setD08StartupBenchmarkIsolation(enabled: Boolean) {
        requireD08Variant()
        d08StartupBenchmarkIsolation = enabled
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun setD08TestPlaintextFallbackPolicy(resolverId: Int, allowed: Boolean) {
        requireD08Variant()
        val revision = ResolverCommandRuntime.revisions.next()
        check(plaintextFallbackFence.requestPolicy(resolverId, revision, allowed))
        check(plaintextFallbackFence.markPersisted(resolverId, revision, allowed))
        check(plaintextFallbackFence.applyStoredPolicy(resolverId, revision, allowed))
        if (!allowed) closePlaintextFallbackSocketsAsync(resolverId, revision)
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun runD08TestPlaintextSend(
        resolverId: Int,
        snapshotAllowsPlaintext: Boolean,
        currentPolicyAllowsPlaintext: () -> Boolean,
        send: () -> Unit
    ): Boolean {
        requireD08Variant()
        return plaintextFallbackFence.sendIfAllowed(
            resolverId,
            snapshotAllowsPlaintext,
            currentPolicyAllowsPlaintext,
            send
        )
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun recordD08TestBlockedDomain(domain: String, reason: DnsDecisionReason) {
        requireD08Variant()
        DnsLogRuntime.recordDomainDecision(domain, reason)
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun setD08TestHttpClient(client: OkHttpClient?) {
        requireD08Variant()
        replaceHttpClient(client)
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun diagnosticsSnapshot(): DnsDiagnosticsSnapshot = DnsLogRuntime.diagnosticsSnapshot()

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun resetD14Diagnostics() {
        requireD14Variant()
        DnsLogRuntime.resetDiagnostics()
        resetD14PacketRejectionCounts()
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun d14PacketRejectionCountsSnapshot(): Map<String, Long> {
        requireD14Variant()
        return PacketRejectionReason.values().associate { reason ->
            reason.name to d14PacketRejectionCounts.get(reason.ordinal)
        }
    }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun resetD14PacketRejectionCounts() {
        requireD14Variant()
        for (reason in PacketRejectionReason.values()) {
            d14PacketRejectionCounts.set(reason.ordinal, 0L)
        }
    }

    private val d14PacketRejectionCounts =
        AtomicLongArray(PacketRejectionReason.values().size)

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal val d14PolicyAssemblyNanos: AtomicLong
        get() {
            requireD14Variant()
            return policyAssemblyNanos
        }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal val d14NetworkChangeCount: AtomicLong
        get() {
            requireD14Variant()
            return networkChangeCount
        }

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal val d14UnderlyingNetworkSnapshot: AtomicReference<UnderlyingNetworkSnapshot?>
        get() {
            requireD14Variant()
            return underlyingNetworkSnapshot
        }

    private val policyAssemblyNanos = AtomicLong(-1L)
    private val networkChangeCount = AtomicLong(0L)
    private val underlyingNetworkSnapshot = AtomicReference<UnderlyingNetworkSnapshot?>(null)

    internal fun upstreamOverride(context: Context): Pair<String, Int>? {
        if (!BuildConfig.D14_DEVICE_TEST) return null
        val preferences = context.getSharedPreferences(D14_TEST_PREFS_NAME, Context.MODE_PRIVATE)
        val host = preferences.getString(D14_TEST_UPSTREAM_HOST_KEY, null)
            ?: throw IOException("D14 test upstream host is missing; refusing non-test DNS.")
        val isLoopbackLiteral = host.matches(Regex("127(?:\\.\\d{1,3}){3}")) ||
            host == "::1" || host == "0:0:0:0:0:0:0:1"
        if (!isLoopbackLiteral) {
            throw IOException("D14 test upstream must be a loopback IP literal.")
        }
        val address = InetAddress.getByName(host)
        if (!address.isLoopbackAddress) {
            throw IOException("D14 test upstream is not loopback.")
        }
        val port = preferences.getInt(D14_TEST_UPSTREAM_PORT_KEY, -1)
            .takeIf { it in 1..65_535 }
            ?: throw IOException("D14 test upstream port is missing or invalid.")
        return (address.hostAddress ?: throw IOException("D14 test upstream host has no IP address.")) to port
    }

    internal fun recordD14PolicyAssemblyNanos(elapsedNanos: Long) {
        if (BuildConfig.D14_DEVICE_TEST) policyAssemblyNanos.set(elapsedNanos)
    }

    internal fun recordD14NetworkSnapshot(
        snapshot: UnderlyingNetworkSnapshot,
        countChange: Boolean = false
    ) {
        if (!BuildConfig.D14_DEVICE_TEST) return
        underlyingNetworkSnapshot.set(snapshot)
        if (countChange) networkChangeCount.incrementAndGet()
    }

    internal fun recordD14PacketRejection(reason: PacketRejectionReason) {
        if (BuildConfig.D14_DEVICE_TEST) d14PacketRejectionCounts.incrementAndGet(reason.ordinal)
    }

    private fun requireD08Variant() {
        check(BuildConfig.APPLICATION_ID.endsWith(".d08test")) {
            "This test hook is available only in the D08 test variant."
        }
    }

    private fun requireD14Variant() {
        check(BuildConfig.D14_DEVICE_TEST) {
            "This test hook is available only in the D14 device-test variant."
        }
    }

    companion object {
        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal const val D14_TEST_PREFS_NAME = "d14_device_test"

        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal const val D14_TEST_UPSTREAM_HOST_KEY = "upstream_host"

        @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
        internal const val D14_TEST_UPSTREAM_PORT_KEY = "upstream_port"
    }
}
