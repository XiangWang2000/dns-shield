package io.github.xiangwang2000.dnsshield.data

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

/** Covers DAO-level server selection and user-rule undo outside the UI and service layers. */
@RunWith(AndroidJUnit4::class)
class DnsDaoInstrumentedTest {
    private lateinit var database: AppDatabase
    private lateinit var dao: DnsDao

    @Before
    fun createDatabase() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        database = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dao = database.dnsDao()
    }

    @After
    fun closeDatabase() {
        database.close()
    }

    @Test
    fun activeLookupReturnsTheLowestIdWhenLegacyRowsShareTheActiveFlag() = runBlocking {
        insertServer(id = 3, active = true)
        insertServer(id = 1, active = true)
        insertServer(id = 2, active = false)

        assertEquals(1, dao.getActiveDnsServer()?.id)
    }

    @Test
    fun activatingAServerDeactivatesEveryOtherRow() = runBlocking {
        insertServer(id = 1, active = true)
        insertServer(id = 2, active = false)
        insertServer(id = 3, active = false)

        assertTrue(dao.setActiveDnsServer(2))

        assertEquals(2, dao.getActiveDnsServer()?.id)
        assertEquals(listOf(2), dao.getDnsServersList().filter { it.isActive }.map { it.id })
    }

    @Test
    fun activatingAMissingServerLeavesTheCurrentSelection() = runBlocking {
        insertServer(id = 1, active = true)

        assertFalse(dao.setActiveDnsServer(99))

        assertEquals(1, dao.getActiveDnsServer()?.id)
    }

    @Test
    fun deletingTheOnlyServerIsRefused() = runBlocking {
        insertServer(id = 1, active = true)

        assertFalse(dao.deleteDnsServerSafely(1))

        assertEquals(1, dao.getDnsServersList().size)
        assertEquals(1, dao.getActiveDnsServer()?.id)
    }

    @Test
    fun deletingTheActiveServerPromotesAnotherBeforeRemoval() = runBlocking {
        insertServer(id = 1, active = true)
        insertServer(id = 2, active = false)
        insertServer(id = 3, active = false)

        assertTrue(dao.deleteDnsServerSafely(1))

        assertEquals(listOf(2, 3), dao.getDnsServersList().map { it.id })
        assertEquals(2, dao.getActiveDnsServer()?.id)
    }

    @Test
    fun deletingAnInactiveServerKeepsTheActiveSelection() = runBlocking {
        insertServer(id = 1, active = true)
        insertServer(id = 2, active = false)

        assertTrue(dao.deleteDnsServerSafely(2))

        assertEquals(listOf(1), dao.getDnsServersList().map { it.id })
        assertEquals(1, dao.getActiveDnsServer()?.id)
    }

    @Test
    fun undoRestoresThePreviousRuleOnlyAtTheCurrentRevisionAndCanRemoveIt() = runBlocking {
        dao.insertUserDomainRule(
            UserDomainRuleEntity(
                domain = "example.com",
                action = "BLOCK",
                includeSubdomains = false,
                revision = "revision-1",
                updatedAtMillis = 1L
            )
        )
        val storedBlock = requireNotNull(dao.getUserDomainRule("example.com", false))

        val allow = storedBlock.copy(action = "ALLOW", revision = "revision-2", updatedAtMillis = 2L)
        assertEquals(storedBlock, dao.replaceUserDomainRule(allow))

        assertFalse(dao.restoreUserDomainRule("example.com", false, "revision-1", storedBlock))
        assertEquals("ALLOW", dao.getUserDomainRule("example.com", false)?.action)

        assertTrue(dao.restoreUserDomainRule("example.com", false, "revision-2", storedBlock))
        val restored = requireNotNull(dao.getUserDomainRule("example.com", false))
        assertEquals("BLOCK", restored.action)
        assertEquals("revision-1", restored.revision)

        val allowAgain = storedBlock.copy(action = "ALLOW", revision = "revision-3", updatedAtMillis = 3L)
        dao.replaceUserDomainRule(allowAgain)

        assertTrue(dao.restoreUserDomainRule("example.com", false, "revision-3", previous = null))
        assertNull(dao.getUserDomainRule("example.com", false))
    }

    private suspend fun insertServer(id: Int, active: Boolean) {
        dao.insertDnsServer(
            DnsServer(
                id = id,
                name = "Resolver $id",
                primaryIp = "192.0.2.$id",
                secondaryIp = null,
                isActive = active
            )
        )
    }
}
