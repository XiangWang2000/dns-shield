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
            .addMigrations(AppDatabase.MIGRATION_1_2)
            .allowMainThreadQueries()
            .build()

        val servers = requireNotNull(database).dnsDao().getDnsServersList()

        assertEquals(1, servers.size)
        assertEquals(7, servers.single().id)
        assertEquals("Existing resolver", servers.single().name)
        assertEquals("203.0.113.53", servers.single().primaryIp)
        assertEquals("203.0.113.54", servers.single().secondaryIp)
        assertTrue(servers.single().allowPlaintextFallback)
        assertNull(servers.single().primaryDohUrl)
        assertNull(servers.single().secondaryDohUrl)
    }
}
