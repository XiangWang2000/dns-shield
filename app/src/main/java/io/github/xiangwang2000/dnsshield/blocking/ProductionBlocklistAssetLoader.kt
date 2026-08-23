package io.github.xiangwang2000.dnsshield.blocking

import android.content.res.AssetManager
import java.nio.ByteBuffer
import java.security.MessageDigest

/** Loads and verifies the pinned production blocklist packaged in the APK. */
class ProductionBlocklistAssetLoader internal constructor(
    private val readArtifact: () -> ByteArray,
    private val contract: ProductionBlocklistArtifactContract = ProductionBlocklistArtifact.contract
) {
    @Volatile
    private var cachedBlocklist: CompiledBlocklist? = null

    fun load(): CompiledBlocklist = cachedBlocklist ?: synchronized(this) {
        cachedBlocklist ?: ProductionBlocklistArtifact
            .verify(readArtifact(), contract)
            .also { cachedBlocklist = it }
    }

    companion object {
        const val ASSET_NAME = "active.bin"

        fun fromAssets(
            assets: AssetManager,
            assetName: String = ASSET_NAME
        ): ProductionBlocklistAssetLoader = ProductionBlocklistAssetLoader(
            readArtifact = {
                assets.open(assetName, AssetManager.ACCESS_BUFFER).use { input ->
                    input.readAtMost(ProductionBlocklistArtifact.contract.artifactSize + 1)
                }
            }
        )
    }
}

internal data class ProductionBlocklistArtifactContract(
    val artifactSize: Int,
    val artifactSha256: String,
    val entryCount: Int
)

internal object ProductionBlocklistArtifact {
    val contract = ProductionBlocklistArtifactContract(
        artifactSize = 823_800,
        artifactSha256 =
            "87737598676f344cafd32c5deb8c0225e07963b5e318ef8c9f099b912487bdbe",
        entryCount = 102_972
    )

    fun verify(
        artifact: ByteArray,
        expected: ProductionBlocklistArtifactContract = contract
    ): CompiledBlocklist {
        require(artifact.size == expected.artifactSize) {
            "Production blocklist size mismatch: expected ${expected.artifactSize}, " +
                "found ${artifact.size}"
        }
        val artifactSha256 = MessageDigest.getInstance("SHA-256")
            .digest(artifact)
            .toArtifactHexString()
        require(artifactSha256 == expected.artifactSha256) {
            "Production blocklist SHA-256 mismatch: expected ${expected.artifactSha256}, " +
                "found $artifactSha256"
        }

        val blocklist = CompiledBlocklist.fromByteBuffer(ByteBuffer.wrap(artifact))
        require(blocklist.entryCount == expected.entryCount) {
            "Production blocklist entry count mismatch: expected ${expected.entryCount}, " +
                "found ${blocklist.entryCount}"
        }
        blocklist.validateSorted()
        return blocklist
    }
}
