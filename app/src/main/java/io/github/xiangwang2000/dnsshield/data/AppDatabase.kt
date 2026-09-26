package io.github.xiangwang2000.dnsshield.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [BypassedApp::class, DnsServer::class, UserDomainRuleEntity::class],
    version = 2,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun dnsDao(): DnsDao

    companion object {
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `user_domain_rules` (
                        `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        `domain` TEXT NOT NULL,
                        `action` TEXT NOT NULL,
                        `includeSubdomains` INTEGER NOT NULL,
                        `revision` TEXT NOT NULL,
                        `updatedAtMillis` INTEGER NOT NULL
                    )
                    """.trimIndent()
                )
                db.execSQL(
                    "CREATE UNIQUE INDEX IF NOT EXISTS `index_user_domain_rules_domain_includeSubdomains` " +
                        "ON `user_domain_rules` (`domain`, `includeSubdomains`)"
                )
            }
        }

        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "dns_shield_database"
                )
                .addMigrations(MIGRATION_1_2)
                .addCallback(object : Callback() {
                    override fun onCreate(db: SupportSQLiteDatabase) {
                        super.onCreate(db)

                        val defaultServers = listOf(
                            arrayOf<Any>("Google DNS", "8.8.8.8", "8.8.4.4", 0, 1),
                            arrayOf<Any>("Cloudflare DNS", "1.1.1.1", "1.0.0.1", 0, 0),
                            arrayOf<Any>("AdGuard (AdBlock)", "94.140.14.14", "94.140.15.15", 0, 0),
                            arrayOf<Any>("Quad9 Secure", "9.9.9.9", "149.112.112.112", 0, 0)
                        )

                        db.beginTransaction()
                        try {
                            defaultServers.forEach { server ->
                                db.execSQL(
                                    """
                                    INSERT INTO dns_servers
                                    (name, primaryIp, secondaryIp, isCustom, isActive)
                                    VALUES (?, ?, ?, ?, ?)
                                    """.trimIndent(),
                                    server
                                )
                            }
                            db.setTransactionSuccessful()
                        } finally {
                            db.endTransaction()
                        }
                    }
                })
                .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
