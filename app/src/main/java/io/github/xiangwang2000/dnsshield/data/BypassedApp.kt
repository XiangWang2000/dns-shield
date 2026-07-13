package io.github.xiangwang2000.dnsshield.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "bypassed_apps")
data class BypassedApp(
    @PrimaryKey val packageName: String,
    val appName: String,
    val isBypassed: Boolean = true
)
