package io.github.xiangwang2000.dnsshield.blocking

import android.content.res.AssetManager
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * Loads and validates one compiled Public Suffix artifact from Android assets.
 *
 * The loader is deliberately not wired into runtime policy yet. A loader instance caches the
 * successfully parsed resolver so callers do not repeatedly read and materialize the same rules.
 */
class PublicSuffixAssetLoader internal constructor(
    private val readArtifact: () -> ByteArray,
    private val contract: PublicSuffixArtifactContract = ProductionPublicSuffixArtifact.contract
) {
    @Volatile
    private var cachedResolver: CompiledPublicSuffixList? = null

    fun load(): CompiledPublicSuffixList = cachedResolver ?: synchronized(this) {
        cachedResolver ?: ProductionPublicSuffixArtifact
            .verify(readArtifact(), contract)
            .also { cachedResolver = it }
    }

    companion object {
        const val ASSET_NAME = "public_suffix.bin"

        fun fromAssets(
            assets: AssetManager,
            assetName: String = ASSET_NAME
        ): PublicSuffixAssetLoader = PublicSuffixAssetLoader(
            readArtifact = {
                assets.open(assetName, AssetManager.ACCESS_BUFFER).use { input ->
                    input.readBytes()
                }
            }
        )
    }
}

internal data class PublicSuffixArtifactContract(
    val artifactSize: Int,
    val artifactSha256: String,
    val normalizedSourceSha256: String,
    val exactRules: Int,
    val wildcardRules: Int,
    val exceptionRules: Int
)

internal object ProductionPublicSuffixArtifact {
    val contract = PublicSuffixArtifactContract(
        artifactSize = 153_740,
        artifactSha256 =
            "401b3ed16ed28eb9a8362a93f8f054462fa16bdce26a0e7eaa6c5a3cb5a6eb70",
        normalizedSourceSha256 =
            "72d07fea544b74d920be2394d4c5fbb38dd3f5f3ccac299e27809009bac1c550",
        exactRules = 9_950,
        wildcardRules = 281,
        exceptionRules = 8
    )

    fun verify(
        artifact: ByteArray,
        expected: PublicSuffixArtifactContract = contract
    ): CompiledPublicSuffixList {
        require(artifact.size == expected.artifactSize) {
            "Public Suffix asset size mismatch: expected ${expected.artifactSize}, " +
                "found ${artifact.size}"
        }
        val artifactSha256 = MessageDigest.getInstance("SHA-256")
            .digest(artifact)
            .toHexString()
        require(artifactSha256 == expected.artifactSha256) {
            "Public Suffix asset SHA-256 mismatch: expected ${expected.artifactSha256}, " +
                "found $artifactSha256"
        }

        val resolver = CompiledPublicSuffixList.fromByteBuffer(ByteBuffer.wrap(artifact))
        require(resolver.sourceSha256Hex == expected.normalizedSourceSha256) {
            "Public Suffix embedded source SHA-256 mismatch: expected " +
                "${expected.normalizedSourceSha256}, found ${resolver.sourceSha256Hex}"
        }
        require(resolver.exactRuleCount == expected.exactRules) {
            "Public Suffix exact rule count mismatch: expected ${expected.exactRules}, " +
                "found ${resolver.exactRuleCount}"
        }
        require(resolver.wildcardRuleCount == expected.wildcardRules) {
            "Public Suffix wildcard rule count mismatch: expected ${expected.wildcardRules}, " +
                "found ${resolver.wildcardRuleCount}"
        }
        require(resolver.exceptionRuleCount == expected.exceptionRules) {
            "Public Suffix exception rule count mismatch: expected ${expected.exceptionRules}, " +
                "found ${resolver.exceptionRuleCount}"
        }
        return resolver
    }
}

private fun ByteArray.toHexString(): String {
    val digits = "0123456789abcdef"
    return buildString(size * 2) {
        for (byte in this@toHexString) {
            val value = byte.toInt() and 0xFF
            append(digits[value ushr 4])
            append(digits[value and 0x0F])
        }
    }
}
