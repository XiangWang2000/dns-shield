package io.github.xiangwang2000.dnsshield.blocking

import java.io.InputStream
import java.nio.ByteBuffer
import java.security.MessageDigest

/** Loads one reviewed production Public Suffix artifact without installing it into runtime policy. */
object PublicSuffixArtifactLoader {
    const val PRODUCTION_ARTIFACT_BYTES = 153_740
    const val PRODUCTION_ARTIFACT_SHA256 =
        "401b3ed16ed28eb9a8362a93f8f054462fa16bdce26a0e7eaa6c5a3cb5a6eb70"
    const val PRODUCTION_SOURCE_SHA256 =
        "72d07fea544b74d920be2394d4c5fbb38dd3f5f3ccac299e27809009bac1c550"
    const val PRODUCTION_EXACT_RULES = 9_950
    const val PRODUCTION_WILDCARD_RULES = 281
    const val PRODUCTION_EXCEPTION_RULES = 8

    data class Loaded(
        val resolver: CompiledPublicSuffixList,
        val artifactBytes: Int,
        val artifactSha256: String
    )

    fun loadProduction(input: InputStream): Loaded {
        val artifact = input.use { it.readBytes() }
        require(artifact.size == PRODUCTION_ARTIFACT_BYTES) {
            "Unexpected Public Suffix artifact size: ${artifact.size}"
        }
        val artifactSha256 = sha256(artifact)
        require(artifactSha256 == PRODUCTION_ARTIFACT_SHA256) {
            "Unexpected Public Suffix artifact SHA-256: $artifactSha256"
        }

        val resolver = CompiledPublicSuffixList.fromByteBuffer(ByteBuffer.wrap(artifact))
        require(resolver.sourceSha256Hex == PRODUCTION_SOURCE_SHA256) {
            "Unexpected Public Suffix normalized-source SHA-256: ${resolver.sourceSha256Hex}"
        }
        require(resolver.exactRuleCount == PRODUCTION_EXACT_RULES) {
            "Unexpected Public Suffix exact-rule count: ${resolver.exactRuleCount}"
        }
        require(resolver.wildcardRuleCount == PRODUCTION_WILDCARD_RULES) {
            "Unexpected Public Suffix wildcard-rule count: ${resolver.wildcardRuleCount}"
        }
        require(resolver.exceptionRuleCount == PRODUCTION_EXCEPTION_RULES) {
            "Unexpected Public Suffix exception-rule count: ${resolver.exceptionRuleCount}"
        }

        return Loaded(resolver, artifact.size, artifactSha256)
    }

    private fun sha256(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(value).toHexString()
}

private fun ByteArray.toHexString(): String = joinToString(separator = "") { byte ->
    "%02x".format(byte.toInt() and 0xff)
}
