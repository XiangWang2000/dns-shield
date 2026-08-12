package io.github.xiangwang2000.dnsshield.service

import io.github.xiangwang2000.dnsshield.blocking.CompiledBlocklistStatus
import io.github.xiangwang2000.dnsshield.blocking.DomainMatcher
import io.github.xiangwang2000.dnsshield.blocking.DomainPolicyAssembly
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class DnsQueryKeyTest {
    @Test
    fun ignoresTransactionIdInEqualityAndHashCode() {
        val firstPayload = byteArrayOf(0x01, 0x02, 0x10, 0x20, 0x30)
        val secondPayload = byteArrayOf(0x7F, 0x55, 0x10, 0x20, 0x30)

        val first = key(firstPayload)
        val second = key(secondPayload)

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
    }

    @Test
    fun includesDnsQuestionAndStateGenerations() {
        val payload = byteArrayOf(0x01, 0x02, 0x10, 0x20, 0x30)

        assertNotEquals(key(payload), key(payload.copyOf().apply { this[4] = 0x31 }))
        assertNotEquals(key(payload, resolverGeneration = 8), key(payload))
        assertNotEquals(key(payload, policyAssembly = policyAssembly()), key(payload))
    }

    @Test
    fun storageCopyOwnsPayloadAndKeepsStableHash() {
        val payload = byteArrayOf(0x01, 0x02, 0x10, 0x20, 0x30)
        val stored = key(payload).copyForStorage()
        val expected = key(payload.copyOf())

        payload[2] = 0x7F

        assertEquals(expected, stored)
        assertEquals(expected.hashCode(), stored.hashCode())
        assertNotEquals(key(payload), stored)
    }

    private fun key(
        payload: ByteArray,
        resolverGeneration: Int = 7,
        policyAssembly: DomainPolicyAssembly = sharedPolicyAssembly
    ) = DnsVpnService.Companion.DnsQueryKey(
        bytes = payload,
        resolverGeneration = resolverGeneration,
        policyAssembly = policyAssembly
    )

    private fun policyAssembly() = DomainPolicyAssembly(
        matcher = DomainMatcher { false },
        compiledBlocklistStatus = CompiledBlocklistStatus.NotConfigured
    )

    private companion object {
        val sharedPolicyAssembly = DomainPolicyAssembly(
            matcher = DomainMatcher { false },
            compiledBlocklistStatus = CompiledBlocklistStatus.NotConfigured
        )
    }
}
