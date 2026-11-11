package io.github.xiangwang2000.dnsshield.data

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class UserDomainRuleSaveTest {
    @Test
    fun oppositeActionRequiresCurrentRevisionConfirmation() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val database = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()

        try {
            val dao = database.dnsDao()
            val originalBlock = UserDomainRuleEntity(
                domain = "example.com",
                action = "BLOCK",
                includeSubdomains = false,
                revision = "block-original"
            )
            assertTrue(dao.saveUserDomainRule(originalBlock, expectedRevision = null))

            val requestedAllow = UserDomainRuleEntity(
                domain = "example.com",
                action = "ALLOW",
                includeSubdomains = false,
                revision = "allow-request"
            )
            assertFalse(dao.saveUserDomainRule(requestedAllow, expectedRevision = null))

            val updatedBlock = originalBlock.copy(revision = "block-updated")
            assertTrue(dao.saveUserDomainRule(updatedBlock, expectedRevision = originalBlock.revision))
            assertFalse(dao.saveUserDomainRule(requestedAllow, expectedRevision = originalBlock.revision))
            assertEquals(originalBlock.action, dao.getUserDomainRule("example.com", false)?.action)
            assertEquals(updatedBlock.revision, dao.getUserDomainRule("example.com", false)?.revision)

            assertTrue(dao.saveUserDomainRule(requestedAllow, expectedRevision = updatedBlock.revision))
            assertEquals(requestedAllow.action, dao.getUserDomainRule("example.com", false)?.action)
        } finally {
            database.close()
        }
    }
}
