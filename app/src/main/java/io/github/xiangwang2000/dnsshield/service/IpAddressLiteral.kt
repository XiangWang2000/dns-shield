package io.github.xiangwang2000.dnsshield.service

import java.net.Inet6Address
import java.net.InetAddress

/** Parses numeric IP literals without consulting the system resolver. */
internal object IpAddressLiteral {
    internal class Parsed internal constructor(
        private val addressBytes: ByteArray,
        val normalized: String,
        private val isIpv6: Boolean
    ) {
        fun toInetAddress(): InetAddress {
            val bytes = addressBytes.copyOf()
            return if (isIpv6) Inet6Address.getByAddress(null, bytes, -1) else InetAddress.getByAddress(bytes)
        }
    }

    fun parse(value: String): Parsed? {
        val ipv4 = parseIpv4(value)
        if (ipv4 != null) {
            return Parsed(ipv4.map(Int::toByte).toByteArray(), ipv4.joinToString("."), isIpv6 = false)
        }
        if (!value.contains(':') || value.any { !it.isHexDigit() && it != ':' && it != '.' }) return null

        val expanded = expandIpv4Suffix(value) ?: return null
        val compressionIndex = expanded.indexOf("::")
        val groups = if (compressionIndex >= 0) {
            if (expanded.indexOf("::", compressionIndex + 2) >= 0) return null
            val left = parseGroups(expanded.substring(0, compressionIndex)) ?: return null
            val right = parseGroups(expanded.substring(compressionIndex + 2)) ?: return null
            val compressedGroupCount = 8 - left.size - right.size
            if (compressedGroupCount < 1) return null

            IntArray(8).also { result ->
                var index = 0
                left.forEach { result[index++] = it }
                index += compressedGroupCount
                right.forEach { result[index++] = it }
            }
        } else {
            val parsedGroups = parseGroups(expanded) ?: return null
            if (parsedGroups.size != 8) return null
            parsedGroups.toIntArray()
        }

        val bytes = ByteArray(16) { index ->
            val group = groups[index / 2]
            if (index % 2 == 0) (group ushr 8).toByte() else group.toByte()
        }
        return Parsed(bytes, normalizeIpv6(groups), isIpv6 = true)
    }

    fun isIpv4(value: String): Boolean = parseIpv4(value) != null

    private fun expandIpv4Suffix(value: String): String? {
        if ('.' !in value) return value
        val separator = value.lastIndexOf(':')
        if (separator < 0) return null
        val octets = parseIpv4(value.substring(separator + 1)) ?: return null
        val firstGroup = (octets[0] shl 8) or octets[1]
        val secondGroup = (octets[2] shl 8) or octets[3]
        return value.substring(0, separator + 1) + firstGroup.toString(16) + ":" + secondGroup.toString(16)
    }

    private fun parseIpv4(value: String): List<Int>? {
        val octets = ArrayList<Int>(4)
        var segmentStart = 0
        value.forEachIndexed { index, char ->
            if (char == '.') {
                if (octets.size >= 3) return null
                octets += parseIpv4Octet(value.substring(segmentStart, index)) ?: return null
                segmentStart = index + 1
            }
        }
        if (octets.size != 3) return null
        octets += parseIpv4Octet(value.substring(segmentStart)) ?: return null
        return octets
    }

    private fun parseIpv4Octet(value: String): Int? {
        if (value.length !in 1..3 || value.any { it !in '0'..'9' }) return null
        val number = value.fold(0) { result, digit -> result * 10 + (digit - '0') }
        return number.takeIf { it in 0..255 }
    }

    private fun parseGroups(value: String): List<Int>? {
        if (value.isEmpty()) return emptyList()
        val groups = ArrayList<Int>(8)
        var segmentStart = 0
        value.forEachIndexed { index, char ->
            if (char == ':') {
                val group = parseGroup(value.substring(segmentStart, index)) ?: return null
                groups += group
                segmentStart = index + 1
            }
        }
        groups += parseGroup(value.substring(segmentStart)) ?: return null
        return groups
    }

    private fun parseGroup(value: String): Int? {
        if (value.length !in 1..4 || value.any { !it.isHexDigit() }) return null
        return value.toIntOrNull(16)
    }

    private fun normalizeIpv6(groups: IntArray): String {
        var bestStart = -1
        var bestLength = 0
        var index = 0
        while (index < groups.size) {
            if (groups[index] != 0) {
                index++
                continue
            }
            val runStart = index
            while (index < groups.size && groups[index] == 0) index++
            val runLength = index - runStart
            if (runLength > bestLength) {
                bestStart = runStart
                bestLength = runLength
            }
        }

        if (bestLength < 2) return groups.joinToString(":") { it.toString(16) }
        val left = groups.take(bestStart).joinToString(":") { it.toString(16) }
        val right = groups.drop(bestStart + bestLength).joinToString(":") { it.toString(16) }
        return when {
            left.isEmpty() && right.isEmpty() -> "::"
            left.isEmpty() -> "::$right"
            right.isEmpty() -> "$left::"
            else -> "$left::$right"
        }
    }

    private fun Char.isHexDigit(): Boolean = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'
}
