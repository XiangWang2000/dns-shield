package io.github.xiangwang2000.dnsshield.data

import androidx.room.Entity
import androidx.room.ColumnInfo
import androidx.room.PrimaryKey

@Entity(tableName = "dns_servers")
data class DnsServer(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val name: String,
    val primaryIp: String,
    val secondaryIp: String?,
    val isCustom: Boolean = false,
    val isActive: Boolean = false,
    @ColumnInfo(defaultValue = "1") val allowPlaintextFallback: Boolean = true,
    val primaryDohUrl: String? = null,
    val primaryDohBootstrapIps: String? = null,
    val secondaryDohUrl: String? = null,
    val secondaryDohBootstrapIps: String? = null
)
