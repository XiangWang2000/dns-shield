package io.github.xiangwang2000.dnsshield.service

import java.io.ByteArrayInputStream
import java.io.InputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNull

class DnsDohResponseValidatorTest {
    @Test
    fun acceptsOnlyBoundedDnsMessagesWithMatchingQuestions() {
        val queryBytes = DnsTestMessages.query()
        val query = (DnsMessageValidator.parseQuery(queryBytes) as DnsQueryParseResult.Valid).query
        val valid = DnsTestMessages.response(queryBytes)

        assertContentEquals(
            valid,
            DnsDohResponseValidator.readValidatedBody(
                "Application/DNS-Message; charset=binary",
                valid.size.toLong(),
                ByteArrayInputStream(valid),
                query
            )
        )
        assertNull(read("text/html", -1, valid, query))
        assertNull(read("application/dns-message", -1, "<html>not DNS</html>".toByteArray(), query))
        assertNull(read("application/dns-message", valid.size.toLong(), valid + 1, query))
        assertNull(read("application/dns-message", -1, DnsTestMessages.response(queryBytes, name = "wrong.example"), query))
    }

    @Test
    fun rejectsAnOversizedUnknownLengthBodyAfterReadingOnlyOneOverflowByte() {
        val queryBytes = DnsTestMessages.query()
        val query = (DnsMessageValidator.parseQuery(queryBytes) as DnsQueryParseResult.Valid).query
        val stream = CountingInputStream(ByteArray(DnsMessageValidator.MAX_DNS_MESSAGE_BYTES + 20))

        assertNull(
            DnsDohResponseValidator.readValidatedBody(
                "application/dns-message",
                -1,
                stream,
                query
            )
        )
        kotlin.test.assertEquals(DnsMessageValidator.MAX_DNS_MESSAGE_BYTES + 1, stream.bytesRead)
    }

    private fun read(type: String, length: Long, bytes: ByteArray, query: ParsedDnsQuery) =
        DnsDohResponseValidator.readValidatedBody(type, length, ByteArrayInputStream(bytes), query)

    private class CountingInputStream(bytes: ByteArray) : ByteArrayInputStream(bytes) {
        var bytesRead = 0
            private set

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int =
            super.read(buffer, offset, length).also { if (it > 0) bytesRead += it }

        override fun read(): Int = super.read().also { if (it >= 0) bytesRead++ }
    }
}
