package io.github.xiangwang2000.dnsshield.service

/** Immutable cache payload with TTLs recalculated on each hit from a monotonic clock. */
internal class DnsResponseCacheEntry private constructor(
    private val responseData: ByteArray,
    private val ttlFields: List<TtlField>,
    private val insertedAtMillis: Long,
    private val lifetimeMillis: Long,
    private val monotonicClock: () -> Long
) {
    fun responseAtCurrentTime(): ByteArray? {
        val elapsedMillis = (monotonicClock() - insertedAtMillis).coerceAtLeast(0L)
        if (elapsedMillis >= lifetimeMillis) return null

        return responseData.copyOf().also { response ->
            ttlFields.forEach { field ->
                // Round remaining lifetime down so downstream caches cannot extend expiry.
                val remainingSeconds = (field.initialTtlSeconds * 1_000L - elapsedMillis) / 1_000L
                writeUnsignedInt(response, field.offset, remainingSeconds)
            }
        }
    }

    private data class TtlField(val offset: Int, val initialTtlSeconds: Long)

    companion object {
        /** Limit cache residency to five minutes without extending any wire TTL. */
        private const val MAX_CACHE_LIFETIME_SECONDS = 300L

        fun create(
            response: ByteArray,
            query: ParsedDnsQuery,
            monotonicClock: () -> Long
        ): DnsResponseCacheEntry? {
            val records = DnsMessageValidator.parseCacheRecordMetadata(response, query) ?: return null
            val flags = readUnsignedShort(response, 2)
            if (flags and 0x0200 != 0) return null

            val extendedRcode = records.firstOrNull { it.type == 41 }
                ?.let { ((it.ttlSeconds ushr 24) and 0xFF).toInt() }
                ?: 0
            val responseCode = (extendedRcode shl 4) or (flags and 0x000F)
            if (responseCode != 0 && responseCode != 3) return null

            val ordinaryRecords = records.filter { it.type != 41 }
            if (ordinaryRecords.isEmpty()) return null

            val answerRecords = ordinaryRecords.filter { it.section == DnsRecordSection.ANSWER }
            val authoritySoas = ordinaryRecords.filter {
                it.section == DnsRecordSection.AUTHORITY && it.type == 6
            }
            val cnameOnlyAnswerWithNegativeAuthority =
                query.question.type != 5 && query.question.type != 255 &&
                    answerRecords.any { it.type == 5 } &&
                    answerRecords.all { it.type == 5 || (it.type == 46 && it.rrsigTypeCovered == 5) } &&
                    authoritySoas.isNotEmpty()
            val negative = responseCode == 3 || answerRecords.isEmpty() || cnameOnlyAnswerWithNegativeAuthority
            val negativeSoas = if (negative) authoritySoas else emptyList()
            if (negative && negativeSoas.isEmpty()) return null

            val negativeSoaOffsets = negativeSoas.associate { record ->
                record.ttlOffset to minOf(record.ttlSeconds, checkNotNull(record.soaMinimumSeconds))
            }
            val ttlFields = ordinaryRecords.map { record ->
                val initialTtl = negativeSoaOffsets[record.ttlOffset] ?: record.ttlSeconds
                if (initialTtl <= 0L) return null
                TtlField(record.ttlOffset, initialTtl)
            }
            val lifetimeSeconds = ttlFields.minOf { it.initialTtlSeconds }
                .coerceAtMost(MAX_CACHE_LIFETIME_SECONDS)
            val storedResponse = response.copyOf().also { copy ->
                negativeSoaOffsets.forEach { (offset, ttl) -> writeUnsignedInt(copy, offset, ttl) }
            }

            return DnsResponseCacheEntry(
                responseData = storedResponse,
                ttlFields = ttlFields,
                insertedAtMillis = monotonicClock(),
                lifetimeMillis = lifetimeSeconds * 1_000L,
                monotonicClock = monotonicClock
            )
        }

        private fun writeUnsignedInt(bytes: ByteArray, offset: Int, value: Long) {
            bytes[offset] = (value ushr 24).toByte()
            bytes[offset + 1] = (value ushr 16).toByte()
            bytes[offset + 2] = (value ushr 8).toByte()
            bytes[offset + 3] = value.toByte()
        }
    }
}
