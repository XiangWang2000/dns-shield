package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertContentEquals

class DnsResponsePacketBuilderTest {
    @Test
    fun stampsTransactionIdDuringPacketCopyWithoutMutatingCachedResponse() {
        val sourceIp = byteArrayOf(10, 0, 0, 1)
        val destinationIp = byteArrayOf(10, 0, 0, 2)
        val transactionId = byteArrayOf(0x12, 0x34)

        listOf(0, 1, 2, 64, 512, 1500).forEach { size ->
            val cachedResponse = ByteArray(size) { it.toByte() }
            val original = cachedResponse.copyOf()
            val legacyResponse = cachedResponse.copyOf().also {
                if (it.size >= 2) {
                    it[0] = transactionId[0]
                    it[1] = transactionId[1]
                }
            }
            val expected = DnsResponsePacketBuilder.build(
                sourceIp,
                destinationIp,
                53,
                53000,
                legacyResponse
            )
            val actual = DnsResponsePacketBuilder.build(
                sourceIp,
                destinationIp,
                53,
                53000,
                cachedResponse,
                transactionId
            )

            assertContentEquals(expected, actual, "payload size $size")
            assertContentEquals(original, cachedResponse, "cached response size $size")
        }
    }
}
