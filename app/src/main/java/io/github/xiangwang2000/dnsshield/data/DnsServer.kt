package io.github.xiangwang2000.dnsshield.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "dns_servers")
data class DnsServer(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val name: String,
    val primaryIp: String,
    val secondaryIp: String?,
    val isCustom: Boolean = false,
    val isActive: Boolean = false
)
