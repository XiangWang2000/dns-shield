package io.github.xiangwang2000.dnsshield.data

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import java.util.UUID

@Entity(
    tableName = "user_domain_rules",
    indices = [Index(value = ["domain", "includeSubdomains"], unique = true)]
)
data class UserDomainRuleEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val domain: String,
    val action: String,
    val includeSubdomains: Boolean,
    val revision: String = UUID.randomUUID().toString(),
    val updatedAtMillis: Long = System.currentTimeMillis()
)
