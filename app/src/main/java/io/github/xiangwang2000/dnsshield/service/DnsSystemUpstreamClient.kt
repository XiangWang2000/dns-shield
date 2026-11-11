package io.github.xiangwang2000.dnsshield.service

import android.annotation.SuppressLint
import android.net.DnsResolver
import android.net.Network
import android.os.Build
import android.os.CancellationSignal
import android.system.ErrnoException
import androidx.annotation.RequiresApi
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.Executor
import kotlin.coroutines.resume

private val systemDnsCallbackExecutor = Executor { it.run() }

@RequiresApi(Build.VERSION_CODES.Q)
internal suspend fun lookupSystemDns(
    network: Network,
    query: ParsedDnsQuery,
    deadline: DnsRequestDeadline,
    onAttempt: () -> Unit,
    logFailure: (String) -> Unit
): ByteArray? {
    val first = queryAndroidResolver(network, query, deadline, onAttempt, logFailure) ?: return null
    val response = first.getOrNull()
    if (response != null) {
        if (DnsMessageValidator.isValidResponse(response, query)) return response
        logFailure("System DNS returned an invalid response (type=${query.question.type}, bytes=${response.size})")
    } else {
        val error = first.exceptionOrNull() as? DnsResolver.DnsException ?: return null
        if (error.code != DnsResolver.ERROR_SYSTEM) return null
    }
    // A larger UDP reply can recover a failed TCP fallback on the same resolver.
    val retryQuery = DnsMessageValidator.withEdnsForSystemRetry(query) ?: return null
    val retryResponse = queryAndroidResolver(network, retryQuery, deadline, onAttempt, logFailure)
        ?.getOrNull() ?: return null
    val clientResponse = if (query.udpPayloadSizeOffset == null) {
        DnsMessageValidator.withoutSyntheticEdns(retryResponse, retryQuery, query)
    } else {
        retryResponse.takeIf { DnsMessageValidator.isValidResponse(it, query) }
    }
    if (clientResponse == null) logFailure("System DNS EDNS retry returned an invalid response")
    return clientResponse
}

// The SDK annotation omits flag = true for the documented rawQuery bitmask.
@SuppressLint("WrongConstant")
@RequiresApi(Build.VERSION_CODES.Q)
@Suppress("DEPRECATION")
private suspend fun queryAndroidResolver(
    network: Network,
    query: ParsedDnsQuery,
    deadline: DnsRequestDeadline,
    onAttempt: () -> Unit,
    logFailure: (String) -> Unit
): Result<ByteArray>? {
    val timeoutMillis = deadline.remainingMillis()
    if (timeoutMillis <= 0L) return null
    return withTimeoutOrNull(timeoutMillis) {
        suspendCancellableCoroutine<Result<ByteArray>> { continuation ->
            val cancellationSignal = CancellationSignal()
            continuation.invokeOnCancellation { cancellationSignal.cancel() }
            if (!continuation.isActive) return@suspendCancellableCoroutine
            onAttempt()
            // DNS Shield owns the answer cache and clears it when the underlay changes.
            DnsResolver.getInstance().rawQuery(
                network,
                DnsMessageValidator.prepareUpstreamQuery(query),
                DnsResolver.FLAG_NO_CACHE_LOOKUP or DnsResolver.FLAG_NO_CACHE_STORE,
                systemDnsCallbackExecutor,
                cancellationSignal,
                object : DnsResolver.Callback<ByteArray> {
                    override fun onAnswer(answer: ByteArray, rcode: Int) {
                        continuation.resume(Result.success(answer))
                    }

                    override fun onError(error: DnsResolver.DnsException) {
                        val errno = (error.cause as? ErrnoException)?.errno
                        logFailure("System DNS attempt failed (type=${query.question.type}, code=${error.code}, errno=$errno)")
                        continuation.resume(Result.failure(error))
                    }
                }
            )
        }
    }
}
