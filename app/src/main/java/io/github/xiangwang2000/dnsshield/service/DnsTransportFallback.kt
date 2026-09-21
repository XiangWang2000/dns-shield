package io.github.xiangwang2000.dnsshield.service

import kotlinx.coroutines.withTimeoutOrNull

internal object DnsTransportFallback {
    suspend fun <T : Any> resolve(
        deadline: DnsRequestDeadline,
        primary: suspend () -> T?,
        fallback: suspend () -> T?,
        onFallback: () -> Unit = {}
    ): T? {
        val remainingMillis = deadline.remainingMillis()
        if (remainingMillis <= 0L) return null

        return withTimeoutOrNull(remainingMillis) {
            val primaryResponse = primary()
            if (deadline.remainingMillis() <= 0L) {
                null
            } else if (primaryResponse != null) {
                primaryResponse
            } else {
                onFallback()
                fallback().takeIf { deadline.remainingMillis() > 0L }
            }
        }
    }
}
