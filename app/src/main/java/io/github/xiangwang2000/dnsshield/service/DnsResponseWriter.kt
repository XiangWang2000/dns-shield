package io.github.xiangwang2000.dnsshield.service

internal fun interface DnsResponseWriter {
    fun send(response: ByteArray)
}

internal object DnsResolvedResponseCommitter {
    fun sendIfCurrent(
        stateLock: Any,
        isCurrent: () -> Boolean,
        response: ByteArray,
        transactionIdSource: ByteArray,
        responseWriter: DnsResponseWriter
    ): Boolean {
        // Validation and the immutable response commit share the resolver-state lock.
        // A later state change cannot turn an uncommitted old response into a send.
        val committedResponse = synchronized(stateLock) {
            if (!isCurrent()) null else response.copyOf().also {
                it[0] = transactionIdSource[0]
                it[1] = transactionIdSource[1]
            }
        } ?: return false
        // Like the TCP handoff, an already committed response may finish after a later update.
        responseWriter.send(committedResponse)
        return true
    }
}
