package io.github.xiangwang2000.dnsshield.blocking

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/**
 * Read-only view over the deterministic binary artifact produced by tools/build_blocklist.py.
 *
 * The supplied buffer must not be modified after construction. Lookups use absolute reads, so
 * they do not mutate shared buffer position and do not allocate a LongArray for the full list.
 */
class CompiledBlocklist private constructor(
    private val data: ByteBuffer,
    val entryCount: Int
) {
    fun containsHash(hash: Long): Boolean {
        var low = 0
        var high = entryCount - 1

        while (low <= high) {
            val middle = (low + high).ushr(1)
            val storedHash = hashAt(middle)
            when {
                java.lang.Long.compareUnsigned(storedHash, hash) < 0 -> low = middle + 1
                java.lang.Long.compareUnsigned(storedHash, hash) > 0 -> high = middle - 1
                else -> return true
            }
        }
        return false
    }

    /**
     * Performs an optional full scan for build-time and test validation.
     *
     * This is intentionally not run by [fromByteBuffer], because scanning a future memory-mapped
     * production list would eagerly touch every file page during startup.
     */
    fun validateSorted() {
        if (entryCount < 2) return

        var previous = hashAt(0)
        for (index in 1 until entryCount) {
            val current = hashAt(index)
            require(java.lang.Long.compareUnsigned(previous, current) < 0) {
                "Blocklist hashes must be strictly sorted as unsigned 64-bit values"
            }
            previous = current
        }
    }

    private fun hashAt(index: Int): Long =
        data.getLong(HEADER_SIZE + index * HASH_SIZE_BYTES)

    companion object {
        private val MAGIC = "DNSHBL01".toByteArray(StandardCharsets.US_ASCII)
        private const val FORMAT_VERSION = 1
        private const val HASH_ALGORITHM_FNV1A_64 = 1
        private const val HEADER_SIZE = 24
        private const val HASH_SIZE_BYTES = Long.SIZE_BYTES

        fun fromByteBuffer(source: ByteBuffer): CompiledBlocklist {
            val data = source
                .slice()
                .asReadOnlyBuffer()
                .order(ByteOrder.LITTLE_ENDIAN)

            require(data.remaining() >= HEADER_SIZE) {
                "Blocklist is smaller than the $HEADER_SIZE-byte header"
            }

            val header = data.duplicate().order(ByteOrder.LITTLE_ENDIAN)
            val magic = ByteArray(MAGIC.size)
            header.get(magic)
            require(magic.contentEquals(MAGIC)) { "Invalid blocklist magic" }

            val version = header.int
            require(version == FORMAT_VERSION) {
                "Unsupported blocklist format version: $version"
            }

            val algorithm = header.int
            require(algorithm == HASH_ALGORITHM_FNV1A_64) {
                "Unsupported blocklist hash algorithm: $algorithm"
            }

            val entryCountLong = header.long
            require(entryCountLong >= 0) {
                "Blocklist entry count must be non-negative: $entryCountLong"
            }
            require(entryCountLong <= Int.MAX_VALUE.toLong()) {
                "Blocklist contains too many entries: $entryCountLong"
            }

            val expectedSize = HEADER_SIZE.toLong() + entryCountLong * HASH_SIZE_BYTES
            require(expectedSize == data.remaining().toLong()) {
                "Blocklist size mismatch: expected $expectedSize bytes, found ${data.remaining()}"
            }

            return CompiledBlocklist(data, entryCountLong.toInt())
        }
    }
}

/** Exact-domain matcher backed by a compiled blocklist. It is not wired into the VPN yet. */
class CompiledBlocklistMatcher(
    private val blocklist: CompiledBlocklist
) : DomainMatcher {
    override fun shouldBlock(domain: String): Boolean {
        val normalized = domain.lowercase().trim()
        if (normalized.isEmpty() || normalized == "unknown") return false
        return blocklist.containsHash(fnv1a64(normalized))
    }
}

internal fun fnv1a64(value: String): Long {
    var hash = FNV_OFFSET_BASIS
    for (byte in value.toByteArray(StandardCharsets.UTF_8)) {
        hash = hash xor (byte.toLong() and 0xFFL)
        hash *= FNV_PRIME
    }
    return hash
}

private const val FNV_OFFSET_BASIS = -3750763034362895579L
private const val FNV_PRIME = 1099511628211L
