package io.github.xiangwang2000.dnsshield.blocking

import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileChannel

/** Loads a compiled blocklist from a local file using a read-only memory mapping. */
object CompiledBlocklistLoader {
    fun fromFile(file: File): CompiledBlocklist {
        require(file.isFile) { "Blocklist file does not exist: ${file.absolutePath}" }
        require(file.length() > 0L) { "Blocklist file is empty: ${file.absolutePath}" }

        RandomAccessFile(file, "r").use { input ->
            val mapped = input.channel.map(
                FileChannel.MapMode.READ_ONLY,
                0L,
                input.length()
            )
            return CompiledBlocklist.fromByteBuffer(mapped)
        }
    }
}
