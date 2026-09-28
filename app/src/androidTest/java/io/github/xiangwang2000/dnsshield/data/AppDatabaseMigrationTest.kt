package io.github.xiangwang2000.dnsshield.data

import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AppDatabaseMigrationTest {
    @Test
    fun migrationAddsRulesWithoutReplacingExistingTablesOrRows() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val helper = FrameworkSQLiteOpenHelperFactory().create(
            SupportSQLiteOpenHelper.Configuration.builder(context)
                .name(null)
                .callback(object : SupportSQLiteOpenHelper.Callback(1) {
                    override fun onCreate(db: SupportSQLiteDatabase) {
                        db.execSQL(
                            "CREATE TABLE `bypassed_apps` (`packageName` TEXT NOT NULL, " +
                                "`appName` TEXT NOT NULL, `isBypassed` INTEGER NOT NULL, " +
                                "PRIMARY KEY(`packageName`))"
                        )
                        db.execSQL(
                            "CREATE TABLE `dns_servers` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                                "`name` TEXT NOT NULL, `primaryIp` TEXT NOT NULL, `secondaryIp` TEXT, " +
                                "`isCustom` INTEGER NOT NULL, `isActive` INTEGER NOT NULL)"
                        )
                        db.execSQL("INSERT INTO bypassed_apps VALUES ('com.example.mail', 'Mail', 1)")
                        db.execSQL("INSERT INTO dns_servers VALUES (1, 'Existing DNS', '9.9.9.9', NULL, 0, 1)")
                    }

                    override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) =
                        error("The migration fixture must remain at schema version 1")
                })
                .build()
        )

        helper.use { openHelper ->
            val db = openHelper.writableDatabase
            AppDatabase.MIGRATION_1_2.migrate(db)

            db.query("SELECT appName, isBypassed FROM bypassed_apps WHERE packageName = 'com.example.mail'")
                .use { cursor ->
                    assertTrue(cursor.moveToFirst())
                    assertEquals("Mail", cursor.getString(0))
                    assertEquals(1, cursor.getInt(1))
                }
            db.query("SELECT name, primaryIp FROM dns_servers WHERE id = 1").use { cursor ->
                assertTrue(cursor.moveToFirst())
                assertEquals("Existing DNS", cursor.getString(0))
                assertEquals("9.9.9.9", cursor.getString(1))
            }

            val columns = mutableSetOf<String>()
            db.query("PRAGMA table_info(`user_domain_rules`)").use { cursor ->
                while (cursor.moveToNext()) columns += cursor.getString(1)
            }
            assertEquals(
                setOf("id", "domain", "action", "includeSubdomains", "revision", "updatedAtMillis"),
                columns
            )

            var uniqueRuleIndexFound = false
            db.query("PRAGMA index_list(`user_domain_rules`)").use { cursor ->
                while (cursor.moveToNext()) {
                    if (cursor.getInt(2) == 1) {
                        val indexName = cursor.getString(1)
                        val indexedColumns = mutableSetOf<String>()
                        db.query("PRAGMA index_info(`$indexName`)").use { indexCursor ->
                            while (indexCursor.moveToNext()) {
                                indexedColumns += indexCursor.getString(2)
                            }
                        }
                        if (indexedColumns == setOf("domain", "includeSubdomains")) {
                            uniqueRuleIndexFound = true
                        }
                    }
                }
            }
            assertTrue("A unique composite domain/scope index must prevent duplicate patterns", uniqueRuleIndexFound)
        }
    }
}
