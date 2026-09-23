package io.github.xiangwang2000.dnsshield.data

import android.content.Context
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DnsServerMigrationTest {
    private lateinit var context: Context
    private val databaseName = "dns_server_migration_test.db"
    private var database: AppDatabase? = null

    @Before
    fun createLegacyDatabase() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        context.deleteDatabase(databaseName)
        val legacy = context.openOrCreateDatabase(databaseName, Context.MODE_PRIVATE, null)
        legacy.execSQL(
            "CREATE TABLE `bypassed_apps` (`packageName` TEXT NOT NULL, `appName` TEXT NOT NULL, " +
                "`isBypassed` INTEGER NOT NULL, PRIMARY KEY(`packageName`))"
        )
        legacy.execSQL(
            "CREATE TABLE `dns_servers` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `name` TEXT NOT NULL, " +
                "`primaryIp` TEXT NOT NULL, `secondaryIp` TEXT, `isCustom` INTEGER NOT NULL, `isActive` INTEGER NOT NULL)"
        )
        legacy.execSQL(
            "INSERT INTO dns_servers (id, name, primaryIp, secondaryIp, isCustom, isActive) " +
                "VALUES (7, 'Existing resolver', '203.0.113.53', '203.0.113.54', 1, 1)"
        )
        legacy.execSQL("INSERT INTO bypassed_apps VALUES ('org.example.mail', 'Mail', 1)")
        legacy.version = 1
        legacy.close()
    }

    @After
    fun closeAndDeleteDatabase() {
        database?.close()
        context.deleteDatabase(databaseName)
    }

    @Test
    fun migrationPreservesResolverRowsAndDefaultsToPlaintextFallback() = runBlocking {
        database = Room.databaseBuilder(context, AppDatabase::class.java, databaseName)
            .addMigrations(AppDatabase.MIGRATION_1_2, AppDatabase.MIGRATION_2_3)
            .allowMainThreadQueries()
            .build()

        val servers = requireNotNull(database).dnsDao().getDnsServersList()

        assertEquals(1, servers.size)
        assertEquals(7, servers.single().id)
        assertEquals("Existing resolver", servers.single().name)
        assertEquals("203.0.113.53", servers.single().primaryIp)
        assertEquals("203.0.113.54", servers.single().secondaryIp)
        assertTrue(servers.single().isCustom)
        assertTrue(servers.single().isActive)
        assertTrue(servers.single().allowPlaintextFallback)
        assertNull(servers.single().primaryDohUrl)
        assertNull(servers.single().secondaryDohUrl)
        assertPreservedBypassAndVersion()
    }

    @Test
    fun migrationFromD07PreservesRulesAndUniqueIndex() = runBlocking {
        context.openOrCreateDatabase(databaseName, Context.MODE_PRIVATE, null).use { legacy ->
            // This is the shipped-to-be D07 v2 schema, not the former D08 draft v2.
            legacy.execSQL(
                "CREATE TABLE user_domain_rules (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                    "domain TEXT NOT NULL, action TEXT NOT NULL, includeSubdomains INTEGER NOT NULL, " +
                    "revision TEXT NOT NULL, updatedAtMillis INTEGER NOT NULL)"
            )
            legacy.execSQL(
                "CREATE UNIQUE INDEX index_user_domain_rules_domain_includeSubdomains " +
                    "ON user_domain_rules (domain, includeSubdomains)"
            )
            legacy.execSQL("INSERT INTO user_domain_rules VALUES (9, 'example.org', 'ALLOW', 1, 'saved-revision', 1234)")
            legacy.version = 2
        }
        database = Room.databaseBuilder(context, AppDatabase::class.java, databaseName)
            .addMigrations(AppDatabase.MIGRATION_1_2, AppDatabase.MIGRATION_2_3)
            .allowMainThreadQueries()
            .build()
        val db = requireNotNull(database)
        val resolver = db.dnsDao().getDnsServersList().single()
        assertEquals(7, resolver.id)
        assertEquals("203.0.113.53", resolver.primaryIp)
        assertTrue(resolver.isCustom)
        assertTrue(resolver.isActive)
        assertTrue(resolver.allowPlaintextFallback)
        assertNull(resolver.primaryDohUrl)
        db.openHelper.readableDatabase.query("SELECT * FROM user_domain_rules WHERE id = 9").use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals("example.org", cursor.getString(cursor.getColumnIndexOrThrow("domain")))
            assertEquals("ALLOW", cursor.getString(cursor.getColumnIndexOrThrow("action")))
            assertEquals(1, cursor.getInt(cursor.getColumnIndexOrThrow("includeSubdomains")))
            assertEquals("saved-revision", cursor.getString(cursor.getColumnIndexOrThrow("revision")))
            assertEquals(1234L, cursor.getLong(cursor.getColumnIndexOrThrow("updatedAtMillis")))
        }
        db.openHelper.writableDatabase.execSQL(
            "INSERT OR IGNORE INTO user_domain_rules " +
                "(domain, action, includeSubdomains, revision, updatedAtMillis) " +
                "VALUES ('example.org', 'BLOCK', 1, 'duplicate', 5678)"
        )
        db.openHelper.readableDatabase.query("SELECT COUNT(*) FROM user_domain_rules").use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals(1, cursor.getInt(0))
        }
        assertPreservedBypassAndVersion()
    }

    private fun assertPreservedBypassAndVersion() {
        val sql = requireNotNull(database).openHelper.readableDatabase
        assertEquals(3, sql.version)
        sql.query("SELECT appName, isBypassed FROM bypassed_apps WHERE packageName = 'org.example.mail'")
            .use { cursor ->
                assertTrue(cursor.moveToFirst())
                assertEquals("Mail", cursor.getString(0))
                assertEquals(1, cursor.getInt(1))
            }
    }
}
