package io.github.xiangwang2000.dnsshield.service

internal object DnsTestMessages {
    fun query(
        name: String = "example.com",
        type: Int = 1,
        clazz: Int = 1,
        transactionId: Int = 0x1234,
        edns: Boolean = false,
        udpPayloadSize: Int = 1232
    ): ByteArray {
        val question = encodeName(name) + byteArrayOf((type ushr 8).toByte(), type.toByte(), (clazz ushr 8).toByte(), clazz.toByte())
        val additional = if (edns) {
            byteArrayOf(
                0, 0, 41, (udpPayloadSize ushr 8).toByte(), udpPayloadSize.toByte(), // root owner and OPT
                0, 0, 0, 0,                 // extended RCODE, version and flags
                0, 0                        // empty RDATA
            )
        } else {
            byteArrayOf()
        }
        val message = ByteArray(12 + question.size + additional.size)
        writeShort(message, 0, transactionId)
        writeShort(message, 2, 0x0100)
        writeShort(message, 4, 1)
        writeShort(message, 10, if (edns) 1 else 0)
        System.arraycopy(question, 0, message, 12, question.size)
        System.arraycopy(additional, 0, message, 12 + question.size, additional.size)
        return message
    }

    fun response(
        query: ByteArray,
        name: String? = null,
        transactionId: Int = readUnsignedShort(query, 0),
        flags: Int = 0x8180
    ): ByteArray {
        val questionEnd = queryQuestionEnd(query)
        val question = encodeName(name ?: questionName(query)) +
            byteArrayOf(query[questionEnd - 4], query[questionEnd - 3], query[questionEnd - 2], query[questionEnd - 1])
        return ByteArray(12 + question.size).also { message ->
            writeShort(message, 0, transactionId)
            writeShort(message, 2, flags)
            writeShort(message, 4, 1)
            System.arraycopy(question, 0, message, 12, question.size)
        }
    }

    fun responseWithAnswer(query: ByteArray, type: Int, data: ByteArray): ByteArray {
        val base = response(query)
        val answerOffset = base.size
        return base.copyOf(base.size + 12 + data.size).also { message ->
            message[6] = 0
            message[7] = 1
            message[answerOffset] = 0xC0.toByte()
            message[answerOffset + 1] = 12
            writeShort(message, answerOffset + 2, type)
            writeShort(message, answerOffset + 4, 1)
            writeShort(message, answerOffset + 10, data.size)
            System.arraycopy(data, 0, message, answerOffset + 12, data.size)
        }
    }

    fun responseWithOpt(
        query: ByteArray,
        extendedRcode: Int,
        section: Int = 2,
        copies: Int = 1
    ): ByteArray {
        val response = response(query)
        val optRecord = byteArrayOf(
            0, 0, 41, 4, 0xD0.toByte(), // root owner, OPT, UDP payload size 1232
            extendedRcode.toByte(), 0, 0, 0, // extended RCODE, version and flags
            0, 0 // empty RDATA
        )
        val countOffset = when (section) {
            0 -> 6
            1 -> 8
            else -> 10
        }
        return response.copyOf(response.size + optRecord.size * copies).also { message ->
            writeShort(message, countOffset, copies)
            repeat(copies) { index ->
                System.arraycopy(optRecord, 0, message, response.size + index * optRecord.size, optRecord.size)
            }
        }
    }

    fun responseWithOptPadding(query: ByteArray, targetSize: Int, udpPayloadSize: Int): ByteArray {
        val response = response(query)
        val recordOffset = response.size
        val optionDataLength = targetSize - recordOffset - 15
        require(optionDataLength >= 0)
        return response.copyOf(targetSize).also { message ->
            writeShort(message, 10, 1)
            message[recordOffset] = 0
            writeShort(message, recordOffset + 1, 41)
            writeShort(message, recordOffset + 3, udpPayloadSize)
            writeShort(message, recordOffset + 9, optionDataLength + 4)
            writeShort(message, recordOffset + 11, 12)
            writeShort(message, recordOffset + 13, optionDataLength)
        }
    }

    fun duplicateAdditionalOpt(query: ByteArray): ByteArray {
        val start = queryQuestionEnd(query)
        val optRecord = query.copyOfRange(start, query.size)
        return query.copyOf(query.size + optRecord.size).also { message ->
            writeShort(message, 10, readUnsignedShort(query, 10) + 1)
            System.arraycopy(optRecord, 0, message, query.size, optRecord.size)
        }
    }

    fun encodedName(name: String): ByteArray = encodeName(name)

    fun parseSimpleResponseIndependently(message: ByteArray): IndependentDnsResponse? {
        if (message.size < 12) return null
        fun readShort(offset: Int): Int =
            ((message[offset].toInt() and 0xFF) shl 8) or (message[offset + 1].toInt() and 0xFF)

        val flags = readShort(2)
        if (flags and 0x8000 == 0 || readShort(4) != 1) return null
        var offset = 12
        val labels = ArrayList<String>()
        while (offset < message.size) {
            val labelLength = message[offset++].toInt() and 0xFF
            if (labelLength == 0) break
            if (labelLength > 63 || labelLength > message.size - offset) return null
            labels += String(message, offset, labelLength, Charsets.US_ASCII)
            offset += labelLength
        }
        if (offset > message.size - 4) return null
        offset += 4
        val answers = readShort(6)
        val authorities = readShort(8)
        val additionals = readShort(10)
        if (answers != 0 || authorities != 0 || additionals != 0 || offset != message.size) return null
        return IndependentDnsResponse(
            name = labels.joinToString("."),
            rcode = flags and 0x0F,
            answerCount = answers,
            authorityCount = authorities,
            additionalCount = additionals
        )
    }

    fun responseWithRecords(
        query: ByteArray,
        answers: List<DnsTestResourceRecord> = emptyList(),
        authorities: List<DnsTestResourceRecord> = emptyList(),
        additionals: List<DnsTestResourceRecord> = emptyList(),
        transactionId: Int = readUnsignedShort(query, 0),
        flags: Int = 0x8180
    ): ByteArray {
        val sections = listOf(answers, authorities, additionals)
        val base = response(query, transactionId = transactionId, flags = flags)
        val recordsSize = sections.sumOf { section -> section.sumOf { it.wireSize() } }
        return base.copyOf(base.size + recordsSize).also { message ->
            writeShort(message, 6, answers.size)
            writeShort(message, 8, authorities.size)
            writeShort(message, 10, additionals.size)

            var offset = base.size
            sections.forEach { section ->
                section.forEach { record ->
                    val owner = when {
                        record.ownerName == null -> byteArrayOf(0xC0.toByte(), 12)
                        record.ownerName.isEmpty() -> byteArrayOf(0)
                        else -> encodeName(record.ownerName)
                    }
                    System.arraycopy(owner, 0, message, offset, owner.size)
                    offset += owner.size
                    writeShort(message, offset, record.type)
                    writeShort(message, offset + 2, record.clazz)
                    writeUnsignedInt(message, offset + 4, record.ttl)
                    writeShort(message, offset + 8, record.data.size)
                    offset += 10
                    System.arraycopy(record.data, 0, message, offset, record.data.size)
                    offset += record.data.size
                }
            }
        }
    }

    fun records(message: ByteArray): List<DnsTestRecordView> {
        require(message.size >= 12)
        var offset = skipWireName(message, 12) + 4
        val result = ArrayList<DnsTestRecordView>()
        val counts = intArrayOf(
            readUnsignedShort(message, 6),
            readUnsignedShort(message, 8),
            readUnsignedShort(message, 10)
        )
        counts.forEachIndexed { section, count ->
            repeat(count) {
                val fieldsOffset = skipWireName(message, offset)
                val dataOffset = fieldsOffset + 10
                val dataLength = readUnsignedShort(message, fieldsOffset + 8)
                result += DnsTestRecordView(
                    section = section,
                    type = readUnsignedShort(message, fieldsOffset),
                    clazz = readUnsignedShort(message, fieldsOffset + 2),
                    ttlOffset = fieldsOffset + 4,
                    ttl = readUnsignedInt(message, fieldsOffset + 4),
                    dataOffset = dataOffset,
                    dataLength = dataLength
                )
                offset = dataOffset + dataLength
                require(offset <= message.size)
            }
        }
        require(offset == message.size)
        return result
    }

    fun queryQuestionEnd(query: ByteArray): Int {
        var offset = 12
        while (true) {
            val length = query[offset].toInt() and 0xFF
            offset++
            if (length == 0) break
            offset += length
        }
        return offset + 4
    }

    fun ipv4UdpDnsPacket(query: ByteArray): ByteArray {
        val packet = ByteArray(20 + 8 + query.size)
        packet[0] = 0x45
        writeShort(packet, 2, packet.size)
        writeShort(packet, 6, 0x4000)
        packet[8] = 64
        packet[9] = 17
        packet[12] = 10
        packet[15] = 2
        packet[16] = 10
        packet[19] = 1
        writeShort(packet, 20, 53000)
        writeShort(packet, 22, 53)
        writeShort(packet, 24, 8 + query.size)
        System.arraycopy(query, 0, packet, 28, query.size)
        return packet
    }

    private fun questionName(query: ByteArray): String {
        val labels = ArrayList<String>()
        var offset = 12
        while (offset < query.size) {
            val length = query[offset++].toInt() and 0xFF
            if (length == 0) break
            labels += String(query, offset, length, Charsets.US_ASCII)
            offset += length
        }
        return labels.joinToString(".")
    }

    private fun encodeName(name: String): ByteArray {
        val output = ArrayList<Byte>()
        name.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            output += bytes.size.toByte()
            bytes.forEach(output::add)
        }
        output += 0
        return output.toByteArray()
    }

    private fun writeShort(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun writeUnsignedInt(bytes: ByteArray, offset: Int, value: Long) {
        require(value in 0..0xFFFF_FFFFL)
        bytes[offset] = (value ushr 24).toByte()
        bytes[offset + 1] = (value ushr 16).toByte()
        bytes[offset + 2] = (value ushr 8).toByte()
        bytes[offset + 3] = value.toByte()
    }

    private fun readUnsignedInt(bytes: ByteArray, offset: Int): Long =
        ((bytes[offset].toLong() and 0xFF) shl 24) or
            ((bytes[offset + 1].toLong() and 0xFF) shl 16) or
            ((bytes[offset + 2].toLong() and 0xFF) shl 8) or
            (bytes[offset + 3].toLong() and 0xFF)

    private fun skipWireName(bytes: ByteArray, startOffset: Int): Int {
        var offset = startOffset
        while (offset < bytes.size) {
            val length = bytes[offset].toInt() and 0xFF
            when {
                length == 0 -> return offset + 1
                length and 0xC0 == 0xC0 -> return offset + 2
                length and 0xC0 != 0 -> error("Invalid DNS name encoding")
                else -> {
                    offset += length + 1
                    require(offset <= bytes.size)
                }
            }
        }
        error("Truncated DNS name")
    }
}

internal data class DnsTestResourceRecord(
    val type: Int,
    val ttl: Long,
    val data: ByteArray,
    val clazz: Int = 1,
    val ownerName: String? = null
) {
    init {
        require(type in 0..0xFFFF)
        require(clazz in 0..0xFFFF)
        require(ttl in 0..0xFFFF_FFFFL)
        require(data.size <= 0xFFFF)
    }

    internal fun wireSize(): Int {
        val ownerSize = when {
            ownerName == null -> 2
            ownerName.isEmpty() -> 1
            else -> ownerName.split('.').sumOf { label -> label.toByteArray(Charsets.US_ASCII).size + 1 } + 1
        }
        return ownerSize + 10 + data.size
    }
}

internal data class DnsTestRecordView(
    val section: Int,
    val type: Int,
    val clazz: Int,
    val ttlOffset: Int,
    val ttl: Long,
    val dataOffset: Int,
    val dataLength: Int
)

internal data class IndependentDnsResponse(
    val name: String,
    val rcode: Int,
    val answerCount: Int,
    val authorityCount: Int,
    val additionalCount: Int
)
