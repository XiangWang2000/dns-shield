package io.github.xiangwang2000.dnsshield.service

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.Locale

internal data class DnsQuestion(
    internal val labels: List<ByteArray>,
    val type: Int,
    val clazz: Int,
    val domainName: String?
) {
    fun matches(other: DnsQuestion): Boolean =
        type == other.type && clazz == other.clazz && labels.size == other.labels.size &&
            labels.indices.all { index ->
                labels[index].contentEquals(other.labels[index], ignoreAsciiCase = true)
            }
}

internal class ParsedDnsQuery internal constructor(
    internal val wire: ByteArray,
    val question: DnsQuestion,
    internal val questionEndOffset: Int,
    internal val opcode: Int,
    val maxUdpResponseBytes: Int,
    internal val udpPayloadSizeOffset: Int?
) {
    val transactionId: Int
        get() = readUnsignedShort(wire, 0)
}

internal sealed interface DnsQueryParseResult {
    data class Valid(val query: ParsedDnsQuery) : DnsQueryParseResult
    data class Rejected(val reason: RejectionReason) : DnsQueryParseResult
}

internal enum class RejectionReason {
    TOO_SHORT,
    TOO_LARGE,
    RESPONSE_PACKET,
    UNSUPPORTED_OPCODE,
    QUESTION_COUNT,
    INVALID_QUESTION,
    INVALID_SECTION,
    TRAILING_DATA
}

internal enum class DnsRecordSection {
    ANSWER,
    AUTHORITY,
    ADDITIONAL
}

internal data class DnsCacheRecordMetadata(
    val type: Int,
    val section: DnsRecordSection,
    val ttlOffset: Int,
    val ttlSeconds: Long,
    val soaMinimumSeconds: Long?
)

internal object DnsMessageValidator {
    const val MAX_DNS_MESSAGE_BYTES = 4096
    private const val HEADER_BYTES = 12
    private const val MAX_NAME_STEPS = 128

    fun parseQuery(message: ByteArray): DnsQueryParseResult {
        if (message.size < HEADER_BYTES) return DnsQueryParseResult.Rejected(RejectionReason.TOO_SHORT)
        if (message.size > MAX_DNS_MESSAGE_BYTES) return DnsQueryParseResult.Rejected(RejectionReason.TOO_LARGE)

        val flags = readUnsignedShort(message, 2)
        if (flags and 0x8000 != 0) return DnsQueryParseResult.Rejected(RejectionReason.RESPONSE_PACKET)
        val opcode = flags ushr 11 and 0x0F
        if (opcode != 0) return DnsQueryParseResult.Rejected(RejectionReason.UNSUPPORTED_OPCODE)
        if (readUnsignedShort(message, 4) != 1) {
            return DnsQueryParseResult.Rejected(RejectionReason.QUESTION_COUNT)
        }

        val parsedQuestion = parseQuestion(message, HEADER_BYTES)
            ?: return DnsQueryParseResult.Rejected(RejectionReason.INVALID_QUESTION)
        val answerCount = readUnsignedShort(message, 6)
        val authorityCount = readUnsignedShort(message, 8)
        val additionalCount = readUnsignedShort(message, 10)
        val endOffset = skipRecords(message, parsedQuestion.nextOffset, answerCount, authorityCount, additionalCount)
            ?: return DnsQueryParseResult.Rejected(RejectionReason.INVALID_SECTION)
        if (endOffset != message.size) return DnsQueryParseResult.Rejected(RejectionReason.TRAILING_DATA)
        val optUdpPayload = findOptUdpPayload(
            message,
            parsedQuestion.nextOffset,
            answerCount,
            authorityCount,
            additionalCount
        )
        val advertisedUdpPayloadSize = optUdpPayload?.size ?: 512

        return DnsQueryParseResult.Valid(
            ParsedDnsQuery(
                wire = message.copyOf(),
                question = parsedQuestion.question,
                questionEndOffset = parsedQuestion.nextOffset,
                opcode = opcode,
                maxUdpResponseBytes = advertisedUdpPayloadSize.coerceAtLeast(512).coerceAtMost(MAX_DNS_MESSAGE_BYTES),
                udpPayloadSizeOffset = optUdpPayload?.classOffset
            )
        )
    }

    fun isValidResponse(response: ByteArray, query: ParsedDnsQuery): Boolean {
        if (response.size < HEADER_BYTES || response.size > MAX_DNS_MESSAGE_BYTES) return false
        if (readUnsignedShort(response, 0) != query.transactionId) return false

        val flags = readUnsignedShort(response, 2)
        if (flags and 0x8000 == 0 || flags ushr 11 and 0x0F != query.opcode) return false
        if (readUnsignedShort(response, 4) != 1) return false

        val parsedQuestion = parseQuestion(response, HEADER_BYTES) ?: return false
        if (!query.question.matches(parsedQuestion.question)) return false

        val endOffset = skipRecords(
            response,
            parsedQuestion.nextOffset,
            readUnsignedShort(response, 6),
            readUnsignedShort(response, 8),
            readUnsignedShort(response, 10)
        ) ?: return false
        if (endOffset != response.size) return false
        return !containsOptRecord(response) || containsOptRecord(query.wire)
    }

    fun isCacheableResponse(response: ByteArray, query: ParsedDnsQuery): Boolean {
        return DnsResponseCacheEntry.create(response, query) { 0L } != null
    }

    internal fun parseCacheRecordMetadata(
        response: ByteArray,
        query: ParsedDnsQuery
    ): List<DnsCacheRecordMetadata>? {
        if (!isValidResponse(response, query)) return null
        val parsedQuestion = parseQuestion(response, HEADER_BYTES) ?: return null
        val sectionCounts = intArrayOf(
            readUnsignedShort(response, 6),
            readUnsignedShort(response, 8),
            readUnsignedShort(response, 10)
        )
        val sections = DnsRecordSection.values()
        val records = ArrayList<DnsCacheRecordMetadata>()
        var offset = parsedQuestion.nextOffset

        sectionCounts.forEachIndexed { sectionIndex, count ->
            repeat(count) {
                val record = parseRecord(response, offset) ?: return null
                val soaMinimum = if (record.type == 6) {
                    parseSoaMinimum(response, record.rdataOffset, record.rdataOffset + record.rdataLength)
                        ?: return null
                } else {
                    null
                }
                records += DnsCacheRecordMetadata(
                    type = record.type,
                    section = sections[sectionIndex],
                    ttlOffset = record.ttlOffset,
                    ttlSeconds = record.ttlSeconds,
                    soaMinimumSeconds = soaMinimum
                )
                offset = record.nextOffset
            }
        }
        return records.takeIf { offset == response.size }
    }

    fun prepareUpstreamQuery(query: ParsedDnsQuery): ByteArray = query.wire.copyOf().also { wire ->
        query.udpPayloadSizeOffset?.let { writeUnsignedShort(wire, it, query.maxUdpResponseBytes) }
    }

    fun buildNxDomainResponse(query: ParsedDnsQuery): ByteArray = buildErrorResponse(query, rcode = 3)

    fun buildServFailResponse(query: ParsedDnsQuery): ByteArray = buildErrorResponse(query, rcode = 2)

    private fun buildErrorResponse(query: ParsedDnsQuery, rcode: Int): ByteArray {
        val response = query.wire.copyOf(query.questionEndOffset)
        val requestFlags = readUnsignedShort(query.wire, 2)
        val responseFlags = 0x8080 or (requestFlags and (0x0100 or 0x0010)) or rcode
        writeUnsignedShort(response, 2, responseFlags)
        writeUnsignedShort(response, 4, 1)
        writeUnsignedShort(response, 6, 0)
        writeUnsignedShort(response, 8, 0)
        writeUnsignedShort(response, 10, 0)
        return response
    }

    private data class ParsedName(val labels: List<ByteArray>, val nextOffset: Int)
    private data class ParsedQuestion(val question: DnsQuestion, val nextOffset: Int)
    private data class ParsedRecord(
        val type: Int,
        val clazz: Int,
        val classOffset: Int,
        val ttlOffset: Int,
        val ttlSeconds: Long,
        val rdataOffset: Int,
        val rdataLength: Int,
        val nextOffset: Int
    )
    private data class OptUdpPayload(val size: Int, val classOffset: Int)

    private fun parseQuestion(message: ByteArray, offset: Int): ParsedQuestion? {
        val name = parseName(message, offset) ?: return null
        if (name.nextOffset > message.size - 4) return null
        val type = readUnsignedShort(message, name.nextOffset)
        val clazz = readUnsignedShort(message, name.nextOffset + 2)
        return ParsedQuestion(
            question = DnsQuestion(name.labels, type, clazz, toDomainName(name.labels)),
            nextOffset = name.nextOffset + 4
        )
    }

    private fun parseName(message: ByteArray, offset: Int): ParsedName? {
        if (offset !in message.indices) return null

        val labels = ArrayList<ByteArray>()
        val visitedOffsets = HashSet<Int>()
        var position = offset
        var nextOffset = -1
        var expandedLength = 1
        var pointerHops = 0

        repeat(MAX_NAME_STEPS) {
            if (position !in message.indices || !visitedOffsets.add(position)) return null
            val length = message[position].toInt() and 0xFF
            when {
                length == 0 -> {
                    if (nextOffset < 0) nextOffset = position + 1
                    return ParsedName(labels, nextOffset)
                }
                length and 0xC0 == 0xC0 -> {
                    if (position + 1 >= message.size) return null
                    val target = ((length and 0x3F) shl 8) or (message[position + 1].toInt() and 0xFF)
                    if (target < HEADER_BYTES || target >= position) return null
                    pointerHops++
                    if (pointerHops > 16) return null
                    if (nextOffset < 0) nextOffset = position + 2
                    position = target
                }
                length and 0xC0 != 0 -> return null
                else -> {
                    if (length > 63 || position + 1 > message.size - length) return null
                    expandedLength += length + 1
                    if (expandedLength > 255) return null
                    labels += message.copyOfRange(position + 1, position + 1 + length)
                    position += length + 1
                }
            }
        }
        return null
    }

    private fun skipRecords(
        message: ByteArray,
        startOffset: Int,
        answerCount: Int,
        authorityCount: Int,
        additionalCount: Int
    ): Int? {
        var offset = startOffset
        val recordCount = answerCount + authorityCount + additionalCount
        if (recordCount > message.size / 11) return null

        var optSeen = false
        intArrayOf(answerCount, authorityCount, additionalCount).forEachIndexed { section, count ->
            repeat(count) {
                val record = parseRecord(message, offset) ?: return null
                if (record.type == 41) {
                    if (section != 2 || optSeen) return null
                    optSeen = true
                }
                offset = record.nextOffset
            }
        }
        return offset
    }

    private fun containsOptRecord(message: ByteArray): Boolean {
        val question = parseQuestion(message, HEADER_BYTES) ?: return false
        val counts = intArrayOf(
            readUnsignedShort(message, 6),
            readUnsignedShort(message, 8),
            readUnsignedShort(message, 10)
        )
        var offset = question.nextOffset

        counts.forEach { count ->
            repeat(count) {
                val record = parseRecord(message, offset) ?: return false
                if (record.type == 41) return true
                offset = record.nextOffset
            }
        }
        return false
    }

    private fun findOptUdpPayload(
        message: ByteArray,
        startOffset: Int,
        answerCount: Int,
        authorityCount: Int,
        additionalCount: Int
    ): OptUdpPayload? {
        var offset = startOffset
        val counts = intArrayOf(answerCount, authorityCount, additionalCount)
        for (count in counts) {
            repeat(count) {
                val record = parseRecord(message, offset) ?: return null
                if (record.type == 41) return OptUdpPayload(record.clazz, record.classOffset)
                offset = record.nextOffset
            }
        }
        return null
    }

    private fun parseRecord(message: ByteArray, offset: Int): ParsedRecord? {
        val ownerName = parseName(message, offset) ?: return null
        val fixedFieldsOffset = ownerName.nextOffset
        if (fixedFieldsOffset > message.size - 10) return null

        val type = readUnsignedShort(message, fixedFieldsOffset)
        val dataLength = readUnsignedShort(message, fixedFieldsOffset + 8)
        val dataStart = fixedFieldsOffset + 10
        if (dataLength > message.size - dataStart) return null
        val dataEnd = dataStart + dataLength
        if (!isValidRecordData(message, type, dataStart, dataEnd, ownerName.labels.isEmpty())) return null

        return ParsedRecord(
            type = type,
            clazz = readUnsignedShort(message, fixedFieldsOffset + 2),
            classOffset = fixedFieldsOffset + 2,
            ttlOffset = fixedFieldsOffset + 4,
            ttlSeconds = readUnsignedInt(message, fixedFieldsOffset + 4),
            rdataOffset = dataStart,
            rdataLength = dataLength,
            nextOffset = dataEnd
        )
    }

    private fun parseSoaMinimum(message: ByteArray, dataStart: Int, dataEnd: Int): Long? {
        val primaryServer = parseName(message, dataStart) ?: return null
        if (primaryServer.nextOffset > dataEnd) return null
        val responsibleMailbox = parseName(message, primaryServer.nextOffset) ?: return null
        if (responsibleMailbox.nextOffset > dataEnd - 20 || dataEnd - responsibleMailbox.nextOffset != 20) {
            return null
        }
        return readUnsignedInt(message, dataEnd - 4)
    }

    private fun isValidRecordData(
        message: ByteArray,
        type: Int,
        dataStart: Int,
        dataEnd: Int,
        ownerIsRoot: Boolean
    ): Boolean {
        fun parseSingleName(start: Int): Boolean =
            parseName(message, start)?.nextOffset == dataEnd

        return when (type) {
            1 -> dataEnd - dataStart == 4
            28 -> dataEnd - dataStart == 16
            2, 5, 12, 39 -> parseSingleName(dataStart)
            6 -> {
                val primaryServer = parseName(message, dataStart) ?: return false
                val responsibleMailbox = parseName(message, primaryServer.nextOffset) ?: return false
                dataEnd - responsibleMailbox.nextOffset == 20
            }
            13 -> parseCharacterStrings(message, dataStart, dataEnd, requiredCount = 2)
            14, 17 -> parseMultipleNames(message, dataStart, dataEnd, prefixBytes = 0, count = 2)
            15, 18, 21, 36 -> parseMultipleNames(message, dataStart, dataEnd, prefixBytes = 2, count = 1)
            16 -> parseCharacterStrings(message, dataStart, dataEnd, requiredCount = 1)
            24, 46 -> {
                if (dataEnd - dataStart < 19) return false
                val signerName = parseName(message, dataStart + 18) ?: return false
                signerName.nextOffset < dataEnd
            }
            25 -> dataEnd - dataStart >= 4
            26 -> parseMultipleNames(message, dataStart, dataEnd, prefixBytes = 2, count = 2)
            33 -> parseMultipleNames(message, dataStart, dataEnd, prefixBytes = 6, count = 1)
            35 -> parseNaptrData(message, dataStart, dataEnd)
            41 -> ownerIsRoot && parseEdnsOptions(message, dataStart, dataEnd)
            43 -> dataEnd - dataStart >= 4
            47 -> parseNsecData(message, dataStart, dataEnd)
            64, 65 -> parseSvcbData(message, dataStart, dataEnd)
            else -> true
        }
    }

    private fun parseMultipleNames(
        message: ByteArray,
        dataStart: Int,
        dataEnd: Int,
        prefixBytes: Int,
        count: Int
    ): Boolean {
        var offset = dataStart + prefixBytes
        if (offset > dataEnd) return false
        repeat(count) {
            val name = parseName(message, offset) ?: return false
            if (name.nextOffset > dataEnd) return false
            offset = name.nextOffset
        }
        return offset == dataEnd
    }

    private fun parseCharacterStrings(message: ByteArray, dataStart: Int, dataEnd: Int, requiredCount: Int = 0): Boolean {
        var offset = dataStart
        var count = 0
        while (offset < dataEnd) {
            val length = message[offset].toInt() and 0xFF
            offset++
            if (length > dataEnd - offset) return false
            offset += length
            count++
        }
        return offset == dataEnd && count >= requiredCount
    }

    private fun parseNaptrData(message: ByteArray, dataStart: Int, dataEnd: Int): Boolean {
        var offset = dataStart + 4
        if (offset > dataEnd) return false
        repeat(3) {
            if (offset >= dataEnd) return false
            val length = message[offset].toInt() and 0xFF
            offset++
            if (length > dataEnd - offset) return false
            offset += length
        }
        return parseName(message, offset)?.nextOffset == dataEnd
    }

    private fun parseEdnsOptions(message: ByteArray, dataStart: Int, dataEnd: Int): Boolean {
        var offset = dataStart
        while (offset < dataEnd) {
            if (dataEnd - offset < 4) return false
            val optionLength = readUnsignedShort(message, offset + 2)
            offset += 4
            if (optionLength > dataEnd - offset) return false
            offset += optionLength
        }
        return offset == dataEnd
    }

    private fun parseNsecData(message: ByteArray, dataStart: Int, dataEnd: Int): Boolean {
        val nextName = parseName(message, dataStart) ?: return false
        var offset = nextName.nextOffset
        var previousWindow = -1
        while (offset < dataEnd) {
            if (dataEnd - offset < 2) return false
            val window = message[offset].toInt() and 0xFF
            val bitmapLength = message[offset + 1].toInt() and 0xFF
            if (window <= previousWindow || bitmapLength !in 1..32 || bitmapLength > dataEnd - offset - 2) {
                return false
            }
            previousWindow = window
            offset += 2 + bitmapLength
        }
        return offset == dataEnd
    }

    private fun parseSvcbData(message: ByteArray, dataStart: Int, dataEnd: Int): Boolean {
        if (dataEnd - dataStart < 3) return false
        val targetName = parseName(message, dataStart + 2) ?: return false
        var offset = targetName.nextOffset
        var previousKey = -1
        while (offset < dataEnd) {
            if (dataEnd - offset < 4) return false
            val key = readUnsignedShort(message, offset)
            val valueLength = readUnsignedShort(message, offset + 2)
            if (key <= previousKey || valueLength > dataEnd - offset - 4) return false
            previousKey = key
            offset += 4 + valueLength
        }
        return offset == dataEnd
    }

    private fun readUnsignedInt(message: ByteArray, offset: Int): Long =
        ((message[offset].toLong() and 0xFF) shl 24) or
            ((message[offset + 1].toLong() and 0xFF) shl 16) or
            ((message[offset + 2].toLong() and 0xFF) shl 8) or
            (message[offset + 3].toLong() and 0xFF)

    private fun toDomainName(labels: List<ByteArray>): String? {
        if (labels.isEmpty()) return "."
        val decoded = ArrayList<String>(labels.size)
        for (label in labels) {
            if (label.isEmpty() || label.any { byte ->
                    val value = byte.toInt() and 0xFF
                    value < 0x21 || value > 0x7E || value == '.'.code || value == '\\'.code
                }) return null
            decoded += String(label, Charsets.US_ASCII)
        }
        return decoded.joinToString(".").lowercase(Locale.ROOT)
    }
}

internal object DnsDohResponseValidator {
    private const val DNS_MEDIA_TYPE = "application/dns-message"

    fun readValidatedBody(
        contentType: String?,
        contentLength: Long,
        stream: InputStream,
        query: ParsedDnsQuery
    ): ByteArray? {
        if (contentType?.substringBefore(';')?.trim()?.equals(DNS_MEDIA_TYPE, ignoreCase = true) != true) {
            return null
        }
        if (contentLength > DnsMessageValidator.MAX_DNS_MESSAGE_BYTES) return null

        val output = ByteArrayOutputStream(minOf(DnsMessageValidator.MAX_DNS_MESSAGE_BYTES, 1024))
        val buffer = ByteArray(1024)
        var totalBytes = 0
        while (true) {
            val remainingWithOverflowByte = DnsMessageValidator.MAX_DNS_MESSAGE_BYTES + 1 - totalBytes
            if (remainingWithOverflowByte <= 0) return null
            val bytesRead = stream.read(buffer, 0, minOf(buffer.size, remainingWithOverflowByte))
            if (bytesRead < 0) break
            if (bytesRead == 0) {
                val nextByte = stream.read()
                if (nextByte < 0) break
                totalBytes++
                if (totalBytes > DnsMessageValidator.MAX_DNS_MESSAGE_BYTES) return null
                output.write(nextByte)
                continue
            }
            totalBytes += bytesRead
            if (totalBytes > DnsMessageValidator.MAX_DNS_MESSAGE_BYTES) return null
            output.write(buffer, 0, bytesRead)
        }

        return output.toByteArray().takeIf { DnsMessageValidator.isValidResponse(it, query) }
    }
}

internal fun readUnsignedShort(bytes: ByteArray, offset: Int): Int =
    ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

private fun writeUnsignedShort(bytes: ByteArray, offset: Int, value: Int) {
    bytes[offset] = (value ushr 8).toByte()
    bytes[offset + 1] = value.toByte()
}

private fun ByteArray.contentEquals(other: ByteArray, ignoreAsciiCase: Boolean): Boolean {
    if (size != other.size) return false
    return indices.all { index ->
        val left = this[index].toInt() and 0xFF
        val right = other[index].toInt() and 0xFF
        if (ignoreAsciiCase) lowerAscii(left) == lowerAscii(right) else left == right
    }
}

private fun lowerAscii(value: Int): Int = if (value in 'A'.code..'Z'.code) value + 32 else value
