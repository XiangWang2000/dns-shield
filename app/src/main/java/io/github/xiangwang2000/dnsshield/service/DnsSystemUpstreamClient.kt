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

/** The observable result of one Android resolver call, free of Android types for JVM tests. */
internal sealed interface SystemDnsAttemptOutcome {
    data class Answer(val response: ByteArray) : SystemDnsAttemptOutcome
    data class Error(val code: Int) : SystemDnsAttemptOutcome
    data object Unavailable : SystemDnsAttemptOutcome
}

internal enum class SystemDnsFirstAttemptAction {
    RETURN_ANSWER,
    RETRY_WITH_EDNS,
    GIVE_UP
}

/**
 * An invalid answer or Android's ERROR_SYSTEM can trigger an EDNS retry.
 * Other Android resolver errors, such as ERROR_PARSE, end the lookup.
 */
internal fun decideFirstSystemDnsAttempt(
    outcome: SystemDnsAttemptOutcome,
    systemErrorCode: Int,
    isValid: (ByteArray) -> Boolean
): SystemDnsFirstAttemptAction = when (outcome) {
    is SystemDnsAttemptOutcome.Answer ->
        if (isValid(outcome.response)) SystemDnsFirstAttemptAction.RETURN_ANSWER
        else SystemDnsFirstAttemptAction.RETRY_WITH_EDNS
    is SystemDnsAttemptOutcome.Error ->
        if (outcome.code == systemErrorCode) SystemDnsFirstAttemptAction.RETRY_WITH_EDNS
        else SystemDnsFirstAttemptAction.GIVE_UP
    SystemDnsAttemptOutcome.Unavailable -> SystemDnsFirstAttemptAction.GIVE_UP
}

@RequiresApi(Build.VERSION_CODES.Q)
internal suspend fun lookupSystemDns(
    network: Network,
    query: ParsedDnsQuery,
    deadline: DnsRequestDeadline,
    onAttempt: () -> Unit,
    logFailure: (String) -> Unit
): ByteArray? {
    val first = queryAndroidResolver(network, query, deadline, onAttempt, logFailure)
    when (
        decideFirstSystemDnsAttempt(first, DnsResolver.ERROR_SYSTEM) {
            DnsMessageValidator.isValidResponse(it, query)
        }
    ) {
        SystemDnsFirstAttemptAction.RETURN_ANSWER ->
            return (first as SystemDnsAttemptOutcome.Answer).response
        SystemDnsFirstAttemptAction.GIVE_UP -> return null
        SystemDnsFirstAttemptAction.RETRY_WITH_EDNS -> Unit
    }
    if (first is SystemDnsAttemptOutcome.Answer) {
        logFailure(
            "System DNS returned an invalid response (type=${query.question.type}, bytes=${first.response.size})"
        )
    }
    // A larger UDP reply can recover a failed TCP fallback on the same resolver.
    val retryQuery = DnsMessageValidator.withEdnsForSystemRetry(query) ?: return null
    val retryOutcome = queryAndroidResolver(network, retryQuery, deadline, onAttempt, logFailure)
    val retryResponse = (retryOutcome as? SystemDnsAttemptOutcome.Answer)?.response ?: return null
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
): SystemDnsAttemptOutcome {
    val timeoutMillis = deadline.remainingMillis()
    if (timeoutMillis <= 0L) return SystemDnsAttemptOutcome.Unavailable
    return withTimeoutOrNull(timeoutMillis) {
        suspendCancellableCoroutine<SystemDnsAttemptOutcome> { continuation ->
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
                        continuation.resume(SystemDnsAttemptOutcome.Answer(answer))
                    }

                    override fun onError(error: DnsResolver.DnsException) {
                        val errno = (error.cause as? ErrnoException)?.errno
                        logFailure("System DNS attempt failed (type=${query.question.type}, code=${error.code}, errno=$errno)")
                        continuation.resume(SystemDnsAttemptOutcome.Error(error.code))
                    }
                }
            )
        }
    } ?: SystemDnsAttemptOutcome.Unavailable
}
