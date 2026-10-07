package io.github.xiangwang2000.dnsshield.service

import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

/** Keep DoH requests on the explicitly configured endpoint, including across redirects. */
internal fun OkHttpClient.forDohEndpoint(endpoint: DnsDohEndpoint): OkHttpClient =
    newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .dns(DohBootstrapDns.forEndpoint(endpoint))
        .build()

internal suspend fun OkHttpClient.lookupDoh(
    endpointUrl: String,
    query: ParsedDnsQuery,
    deadline: DnsRequestDeadline,
    attemptTimeoutMillis: Long? = null,
    onCallQueued: () -> Unit = {},
    logFailure: (String, Throwable?) -> Unit
): ByteArray? {
    val remainingMillis = deadline.remainingMillis()
    if (remainingMillis <= 0L) return null
    val callTimeoutMillis = attemptTimeoutMillis?.let { minOf(remainingMillis, it) } ?: remainingMillis
    if (callTimeoutMillis <= 0L) return null

    val mediaType = "application/dns-message".toMediaType()
    val requestBody = DnsMessageValidator.prepareUpstreamQuery(query).toRequestBody(mediaType)
    val request = Request.Builder()
        .url(endpointUrl)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .post(requestBody)
        .build()
    val call = newCall(request)
    call.timeout().timeout(callTimeoutMillis, TimeUnit.MILLISECONDS)

    return suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { call.cancel() }
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (continuation.isActive) {
                    logFailure("DoH resolution failed for $endpointUrl", e)
                    continuation.resume(null)
                }
            }

            override fun onResponse(call: Call, response: Response) {
                try {
                    if (continuation.isActive) {
                        if (response.isSuccessful && response.request.url.isHttps) {
                            val body = response.body
                            val bytes = DnsDohResponseValidator.readValidatedBody(
                                contentType = response.header("Content-Type"),
                                contentLength = body.contentLength(),
                                stream = body.byteStream(),
                                query = query
                            )
                            continuation.resume(bytes)
                        } else {
                            logFailure("DoH resolution error: HTTP ${response.code} for $endpointUrl", null)
                            continuation.resume(null)
                        }
                    } else {
                        response.close()
                    }
                } catch (e: Exception) {
                    logFailure("Failed reading DoH body bytes", e)
                    if (continuation.isActive) continuation.resume(null)
                } finally {
                    try {
                        response.close()
                    } catch (_: Exception) {
                    }
                }
            }
        })
        onCallQueued()
    }
}
