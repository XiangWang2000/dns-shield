package io.github.xiangwang2000.dnsshield.blocking

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.TreeMap
import java.util.TreeSet

/**
 * A deterministic, versioned binary artifact for a future mapped blocklist.
 *
 * The format deliberately contains only fixed-width 128-bit SHA-256 fingerprints:
 * a four-byte magic value, a version, an entry count, then sorted fingerprints.
 * Keeping the format independent from the VPN service makes its production and
 * validation reproducible before it is introduced into the DNS hot path.
 */
data class HashBlocklistArtifact(
    val bytes: ByteArray,
    val entryCount: Int,
    val sha256: String
)

object HashBlocklistArtifactBuilder {
    private const val VERSION = 1
    private const val HEADER_SIZE = 12
    private const val FINGERPRINT_SIZE = 16
    private val magic = byteArrayOf('D'.code.toByte(), 'S'.code.toByte(), 'H'.code.toByte(), 'B'.code.toByte())

    /** Builds a canonical artifact from raw domains, ignoring blank and unknown values. */
    fun build(domains: Iterable<String>): HashBlocklistArtifact {
        val normalizedDomains = TreeSet<String>()
        for (domain in domains) {
            normalize(domain)
                .takeIf { it.isNotEmpty() && it != "unknown" }
                ?.let(normalizedDomains::add)
        }

        val fingerprints = TreeMap<String, String>()
        for (domain in normalizedDomains) {
            val fingerprint = fingerprintHex(domain)
            val previousDomain = fingerprints[fingerprint]
            require(previousDomain == null || previousDomain == domain) {
                "128-bit fingerprint collision between $previousDomain and $domain"
            }
            fingerprints[fingerprint] = domain
        }

        val artifactSize = artifactSize(fingerprints.size)
        val bytes = ByteBuffer.allocate(artifactSize)
            .order(ByteOrder.BIG_ENDIAN)
            .put(magic)
            .putInt(VERSION)
            .putInt(fingerprints.size)
            .apply {
                fingerprints.keys.forEach { put(hexToBytes(it)) }
            }
            .array()

        return HashBlocklistArtifact(
            bytes = bytes,
            entryCount = fingerprints.size,
            sha256 = sha256(bytes)
        )
    }

    /** Validates an artifact without loading it into any matcher implementation. */
    fun inspect(bytes: ByteArray): HashBlocklistArtifact {
        require(bytes.size >= HEADER_SIZE) { "Artifact is shorter than its header" }

        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
        val actualMagic = ByteArray(magic.size)
        buffer.get(actualMagic)
        require(actualMagic.contentEquals(magic)) { "Unsupported artifact magic" }
        require(buffer.int == VERSION) { "Unsupported artifact version" }

        val entryCount = buffer.int
        require(entryCount >= 0) { "Artifact entry count must not be negative" }
        require(bytes.size == artifactSize(entryCount)) { "Artifact size does not match its entry count" }

        var previousFingerprint: String? = null
        repeat(entryCount) {
            val fingerprint = ByteArray(FINGERPRINT_SIZE)
            buffer.get(fingerprint)
            val currentFingerprint = fingerprint.toHex()
            require(previousFingerprint == null || previousFingerprint < currentFingerprint) {
                "Artifact fingerprints must be strictly sorted"
            }
            previousFingerprint = currentFingerprint
        }

        return HashBlocklistArtifact(
            bytes = bytes.copyOf(),
            entryCount = entryCount,
            sha256 = sha256(bytes)
        )
    }

    private fun artifactSize(entryCount: Int): Int {
        val size = HEADER_SIZE.toLong() + entryCount.toLong() * FINGERPRINT_SIZE
        require(size <= Int.MAX_VALUE) { "Artifact is too large to build in memory" }
        return size.toInt()
    }

    private fun normalize(domain: String): String = domain.lowercase().trim()

    private fun fingerprintHex(domain: String): String = MessageDigest
        .getInstance("SHA-256")
        .digest(domain.toByteArray(Charsets.UTF_8))
        .copyOf(FINGERPRINT_SIZE)
        .toHex()

    private fun sha256(bytes: ByteArray): String = MessageDigest
        .getInstance("SHA-256")
        .digest(bytes)
        .toHex()

    private fun hexToBytes(hex: String): ByteArray = ByteArray(hex.length / 2) { index ->
        hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }

    private fun ByteArray.toHex(): String = joinToString(separator = "") {
        (it.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}
