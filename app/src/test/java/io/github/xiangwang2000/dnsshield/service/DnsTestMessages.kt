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

    fun responseWithARecords(
        query: ByteArray,
        answerCount: Int,
        authorityCount: Int = 0,
        additionalCount: Int = 0
    ): ByteArray {
        val response = response(query)
        val record = byteArrayOf(
            0xC0.toByte(), 12, // owner name points to the question
            0, 1, 0, 1,       // A, IN
            0, 0, 0, 60,      // TTL
            0, 4, 192.toByte(), 0, 2, 1
        )
        val recordCount = answerCount + authorityCount + additionalCount
        return response.copyOf(response.size + record.size * recordCount).also { message ->
            writeShort(message, 6, answerCount)
            writeShort(message, 8, authorityCount)
            writeShort(message, 10, additionalCount)
            repeat(recordCount) { index ->
                System.arraycopy(record, 0, message, response.size + index * record.size, record.size)
            }
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
}

internal data class IndependentDnsResponse(
    val name: String,
    val rcode: Int,
    val answerCount: Int,
    val authorityCount: Int,
    val additionalCount: Int
)
