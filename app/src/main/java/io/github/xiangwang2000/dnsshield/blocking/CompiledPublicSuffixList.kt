package io.github.xiangwang2000.dnsshield.blocking

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import kotlin.math.max

/**
 * Deterministic Public Suffix resolver backed by the compact artifact produced by
 * `tools/build_public_suffix.py`.
 *
 * The artifact contains rules from both ICANN and PRIVATE sections. This component is pure Kotlin
 * and is not installed into runtime policy until a production source and performance measurements
 * are reviewed separately.
 */
class CompiledPublicSuffixList private constructor(
    private val exactRules: Set<String>,
    private val wildcardSuffixes: Set<String>,
    private val exceptionRules: Set<String>,
    sourceSha256: ByteArray
) : RegistrableDomainResolver {
    val exactRuleCount: Int = exactRules.size
    val wildcardRuleCount: Int = wildcardSuffixes.size
    val exceptionRuleCount: Int = exceptionRules.size
    val sourceSha256Hex: String = sourceSha256.toHexString()

    override fun registrableDomain(domain: String): String? {
        val normalized = domain.lowercase().trim()
        if (!isUsableDomain(normalized)) return null

        val labels = normalized.split('.')
        if (labels.size < 2) return null

        var prevailingRuleLabels = 1 // Public Suffix default rule: "*".
        var exceptionRuleLabels = 0

        for (index in labels.indices) {
            val suffix = labels.subList(index, labels.size).joinToString(".")
            val suffixLabelCount = labels.size - index

            if (suffix in exceptionRules) {
                exceptionRuleLabels = max(exceptionRuleLabels, suffixLabelCount)
            }
            if (suffix in exactRules) {
                prevailingRuleLabels = max(prevailingRuleLabels, suffixLabelCount)
            }
            if (index > 0 && suffix in wildcardSuffixes) {
                prevailingRuleLabels = max(prevailingRuleLabels, suffixLabelCount + 1)
            }
        }

        val publicSuffixLabels = if (exceptionRuleLabels > 0) {
            exceptionRuleLabels - 1
        } else {
            prevailingRuleLabels
        }
        if (labels.size <= publicSuffixLabels) return null

        return labels.takeLast(publicSuffixLabels + 1).joinToString(".")
    }

    companion object {
        private val MAGIC = "DNSHPS01".toByteArray(StandardCharsets.US_ASCII)
        private const val FORMAT_VERSION = 1
        private const val FLAG_INCLUDES_PRIVATE = 1
        private const val SUPPORTED_FLAGS = FLAG_INCLUDES_PRIVATE
        private const val SOURCE_SHA256_SIZE = 32
        private const val HEADER_SIZE = 60
        private const val MIN_ENCODED_RULE_SIZE = 3 // uint16 length plus one UTF-8 byte.

        fun fromByteBuffer(source: ByteBuffer): CompiledPublicSuffixList {
            val data = source
                .slice()
                .asReadOnlyBuffer()
                .order(ByteOrder.LITTLE_ENDIAN)

            require(data.remaining() >= HEADER_SIZE) {
                "Public Suffix artifact is smaller than the $HEADER_SIZE-byte header"
            }

            val magic = ByteArray(MAGIC.size)
            data.get(magic)
            require(magic.contentEquals(MAGIC)) { "Invalid Public Suffix artifact magic" }

            val version = data.int
            require(version == FORMAT_VERSION) {
                "Unsupported Public Suffix artifact version: $version"
            }

            val flags = data.int
            require(flags and SUPPORTED_FLAGS == flags) {
                "Unsupported Public Suffix artifact flags: $flags"
            }
            require(flags and FLAG_INCLUDES_PRIVATE != 0) {
                "Public Suffix artifact must include PRIVATE rules"
            }

            val exactCount = readCount(data, "exact")
            val wildcardCount = readCount(data, "wildcard")
            val exceptionCount = readCount(data, "exception")
            val sourceSha256 = ByteArray(SOURCE_SHA256_SIZE)
            data.get(sourceSha256)

            val exactRules = readRules(data, exactCount, "exact")
            val wildcardSuffixes = readRules(data, wildcardCount, "wildcard")
            val exceptionRules = readRules(data, exceptionCount, "exception")
            require(!data.hasRemaining()) {
                "Public Suffix artifact contains ${data.remaining()} trailing bytes"
            }

            return CompiledPublicSuffixList(
                exactRules = exactRules,
                wildcardSuffixes = wildcardSuffixes,
                exceptionRules = exceptionRules,
                sourceSha256 = sourceSha256
            )
        }

        private fun readCount(data: ByteBuffer, category: String): Int {
            val count = data.int
            require(count >= 0) { "Public Suffix $category rule count must be non-negative" }
            return count
        }

        private fun readRules(
            data: ByteBuffer,
            count: Int,
            category: String
        ): Set<String> {
            require(count <= data.remaining() / MIN_ENCODED_RULE_SIZE) {
                "Public Suffix $category rule count exceeds remaining artifact bytes"
            }

            val rules = LinkedHashSet<String>(count)
            var previousBytes: ByteArray? = null
            repeat(count) {
                require(data.remaining() >= Short.SIZE_BYTES) {
                    "Public Suffix $category rule length is truncated"
                }
                val length = data.short.toInt() and 0xFFFF
                require(length > 0) { "Public Suffix $category rule must not be empty" }
                require(length <= data.remaining()) {
                    "Public Suffix $category rule is truncated"
                }

                val bytes = ByteArray(length)
                data.get(bytes)
                previousBytes?.let { previous ->
                    require(compareUnsigned(previous, bytes) < 0) {
                        "Public Suffix $category rules must be strictly sorted by UTF-8 bytes"
                    }
                }
                previousBytes = bytes

                val rule = decodeUtf8(bytes)
                require(rule == rule.lowercase().trim() && isUsableDomain(rule)) {
                    "Malformed Public Suffix $category rule: $rule"
                }
                require(rules.add(rule)) {
                    "Duplicate Public Suffix $category rule: $rule"
                }
            }
            return rules
        }

        private fun decodeUtf8(bytes: ByteArray): String =
            StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()

        private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
            val commonLength = minOf(left.size, right.size)
            for (index in 0 until commonLength) {
                val difference =
                    (left[index].toInt() and 0xFF) - (right[index].toInt() and 0xFF)
                if (difference != 0) return difference
            }
            return left.size - right.size
        }

        private fun isUsableDomain(domain: String): Boolean =
            domain.isNotEmpty() &&
                domain != "unknown" &&
                !domain.startsWith('.') &&
                !domain.endsWith('.') &&
                ".." !in domain &&
                domain.none {
                    it.isWhitespace() || it == '/' || it == '*' || it == '!'
                } &&
                domain.split('.').all { label ->
                    label.isNotEmpty() && !label.startsWith('-') && !label.endsWith('-')
                }
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
