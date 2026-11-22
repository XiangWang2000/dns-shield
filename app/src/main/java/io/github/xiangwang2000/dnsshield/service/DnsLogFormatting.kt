package io.github.xiangwang2000.dnsshield.service

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Formatting helpers used while assembling per-query log lines.
 *
 * Constructing `SimpleDateFormat` and calling `String.format` once per DNS query is measurable
 * on the hot path, so both helpers stay allocation-light and confine the mutable formatter to the
 * calling thread.
 */
internal object DnsLogFormatting {
    private const val HEX_DIGITS = "0123456789ABCDEF"

    private val timestampFormatter = object : ThreadLocal<SimpleDateFormat>() {
        override fun initialValue(): SimpleDateFormat =
            SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    }

    private val timestampDate = object : ThreadLocal<Date>() {
        override fun initialValue(): Date = Date()
    }

    fun transactionId(payload: ByteArray): String {
        if (payload.size < 2) return "Unknown"
        val high = payload[0].toInt() and 0xFF
        val low = payload[1].toInt() and 0xFF
        val buffer = StringBuilder(6)
        buffer.append("0x")
        buffer.append(HEX_DIGITS[high ushr 4])
        buffer.append(HEX_DIGITS[high and 0x0F])
        buffer.append(HEX_DIGITS[low ushr 4])
        buffer.append(HEX_DIGITS[low and 0x0F])
        return buffer.toString()
    }

    fun timestamp(nowMillis: Long): String {
        val date = timestampDate.get()!!
        date.time = nowMillis
        return timestampFormatter.get()!!.format(date)
    }
}
