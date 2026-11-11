package io.github.xiangwang2000.dnsshield.data

import android.content.Context
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
            .addMigrations(AppDatabase.MIGRATION_1_2, AppDatabase.MIGRATION_2_3, AppDatabase.MIGRATION_3_4)
            .allowMainThreadQueries()
            .build()

        val servers = requireNotNull(database).dnsDao().getDnsServersList()

        assertEquals(2, servers.size)
        val existingResolver = servers.single { it.id == 7 }
        assertEquals(7, existingResolver.id)
        assertEquals("Existing resolver", existingResolver.name)
        assertEquals("203.0.113.53", existingResolver.primaryIp)
        assertEquals("203.0.113.54", existingResolver.secondaryIp)
        assertTrue(existingResolver.isCustom)
        assertTrue(existingResolver.isActive)
        assertTrue(existingResolver.allowPlaintextFallback)
        assertEquals(DnsResolverMode.CONFIGURED, existingResolver.resolverMode)
        assertNull(existingResolver.primaryDohUrl)
        assertNull(existingResolver.secondaryDohUrl)
        assertSystemDnsPreset(servers.single { it.resolverMode == DnsResolverMode.SYSTEM })
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
            .addMigrations(AppDatabase.MIGRATION_1_2, AppDatabase.MIGRATION_2_3, AppDatabase.MIGRATION_3_4)
            .allowMainThreadQueries()
            .build()
        val db = requireNotNull(database)
        val resolver = db.dnsDao().getDnsServersList().single { it.id == 7 }
        assertEquals(7, resolver.id)
        assertEquals("203.0.113.53", resolver.primaryIp)
        assertTrue(resolver.isCustom)
        assertTrue(resolver.isActive)
        assertTrue(resolver.allowPlaintextFallback)
        assertEquals(DnsResolverMode.CONFIGURED, resolver.resolverMode)
        assertNull(resolver.primaryDohUrl)
        assertSystemDnsPreset(db.dnsDao().getDnsServersList().single { it.resolverMode == DnsResolverMode.SYSTEM })
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

    @Test
    fun migrationFromV3PreservesExistingResolverAndTlsSettings() = runBlocking {
        context.deleteDatabase(databaseName)
        context.openOrCreateDatabase(databaseName, Context.MODE_PRIVATE, null).use { legacy ->
            legacy.execSQL(
                "CREATE TABLE bypassed_apps (packageName TEXT NOT NULL, appName TEXT NOT NULL, " +
                    "isBypassed INTEGER NOT NULL, PRIMARY KEY(packageName))"
            )
            legacy.execSQL(
                "CREATE TABLE dns_servers (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, name TEXT NOT NULL, " +
                    "primaryIp TEXT NOT NULL, secondaryIp TEXT, isCustom INTEGER NOT NULL, isActive INTEGER NOT NULL, " +
                    "allowPlaintextFallback INTEGER NOT NULL DEFAULT 1, primaryDohUrl TEXT, " +
                    "primaryDohBootstrapIps TEXT, secondaryDohUrl TEXT, secondaryDohBootstrapIps TEXT)"
            )
            legacy.execSQL(
                "CREATE TABLE user_domain_rules (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                    "domain TEXT NOT NULL, action TEXT NOT NULL, includeSubdomains INTEGER NOT NULL, " +
                    "revision TEXT NOT NULL, updatedAtMillis INTEGER NOT NULL)"
            )
            legacy.execSQL(
                "CREATE UNIQUE INDEX index_user_domain_rules_domain_includeSubdomains " +
                    "ON user_domain_rules (domain, includeSubdomains)"
            )
            legacy.execSQL(
                "INSERT INTO dns_servers (id, name, primaryIp, secondaryIp, isCustom, isActive, " +
                    "allowPlaintextFallback, primaryDohUrl, primaryDohBootstrapIps, secondaryDohUrl, secondaryDohBootstrapIps) " +
                    "VALUES (7, 'Existing resolver', '203.0.113.53', '203.0.113.54', 1, 1, 0, " +
                    "'https://dns.example/primary', '203.0.113.55', 'https://dns.example/secondary', '203.0.113.56')"
            )
            legacy.execSQL("INSERT INTO bypassed_apps VALUES ('org.example.mail', 'Mail', 1)")
            legacy.execSQL("INSERT INTO user_domain_rules VALUES (9, 'example.org', 'ALLOW', 1, 'saved-revision', 1234)")
            legacy.version = 3
        }
        database = Room.databaseBuilder(context, AppDatabase::class.java, databaseName)
            .addMigrations(AppDatabase.MIGRATION_3_4)
            .allowMainThreadQueries()
            .build()

        val db = requireNotNull(database)
        val servers = db.dnsDao().getDnsServersList()
        assertEquals(2, servers.size)
        val resolver = servers.single { it.id == 7 }
        assertEquals("Existing resolver", resolver.name)
        assertEquals("203.0.113.53", resolver.primaryIp)
        assertEquals("203.0.113.54", resolver.secondaryIp)
        assertTrue(resolver.isCustom)
        assertTrue(resolver.isActive)
        assertFalse(resolver.allowPlaintextFallback)
        assertEquals("https://dns.example/primary", resolver.primaryDohUrl)
        assertEquals("203.0.113.55", resolver.primaryDohBootstrapIps)
        assertEquals("https://dns.example/secondary", resolver.secondaryDohUrl)
        assertEquals("203.0.113.56", resolver.secondaryDohBootstrapIps)
        assertEquals(DnsResolverMode.CONFIGURED, resolver.resolverMode)
        assertSystemDnsPreset(servers.single { it.resolverMode == DnsResolverMode.SYSTEM })
        db.openHelper.readableDatabase.query("SELECT revision, updatedAtMillis FROM user_domain_rules WHERE id = 9").use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals("saved-revision", cursor.getString(0))
            assertEquals(1234L, cursor.getLong(1))
        }
        assertPreservedBypassAndVersion()
    }

    private fun assertSystemDnsPreset(server: DnsServer) {
        assertEquals("系統 DNS", server.name)
        assertEquals("", server.primaryIp)
        assertNull(server.secondaryIp)
        assertFalse(server.isCustom)
        assertFalse(server.isActive)
        assertTrue(server.allowPlaintextFallback)
        assertNull(server.primaryDohUrl)
        assertNull(server.primaryDohBootstrapIps)
        assertNull(server.secondaryDohUrl)
        assertNull(server.secondaryDohBootstrapIps)
        assertEquals(DnsResolverMode.SYSTEM, server.resolverMode)
    }

    private fun assertPreservedBypassAndVersion() {
        val sql = requireNotNull(database).openHelper.readableDatabase
        assertEquals(4, sql.version)
        sql.query("SELECT appName, isBypassed FROM bypassed_apps WHERE packageName = 'org.example.mail'")
            .use { cursor ->
                assertTrue(cursor.moveToFirst())
                assertEquals("Mail", cursor.getString(0))
                assertEquals(1, cursor.getInt(1))
            }
    }
}
