package io.github.xiangwang2000.dnsshield.blocking

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertIs

class DomainPolicyAssemblerUnsortedTest {
    @Test
    fun rejectsUnsortedCompiledArtifactBeforeAddingMatcher() {
        val artifact = ByteBuffer.allocate(40)
            .order(ByteOrder.LITTLE_ENDIAN)
            .apply {
                put("DNSHBL01".toByteArray(StandardCharsets.US_ASCII))
                putInt(1)
                putInt(1)
                putLong(2L)
                putLong(Long.MIN_VALUE)
                putLong(Long.MAX_VALUE)
                flip()
            }
        val file = File.createTempFile("dns-shield-unsorted-", ".bin").apply {
            writeBytes(artifact.array())
            deleteOnExit()
        }

        val assembly = DomainPolicyAssembler.assemble(compiledBlocklistFile = file)

        assertIs<CompiledBlocklistStatus.Rejected>(assembly.compiledBlocklistStatus)
    }
}
