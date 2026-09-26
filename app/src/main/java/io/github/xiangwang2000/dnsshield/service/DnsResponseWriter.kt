package io.github.xiangwang2000.dnsshield.service

internal fun interface DnsResponseWriter {
    fun send(response: ByteArray)
}
