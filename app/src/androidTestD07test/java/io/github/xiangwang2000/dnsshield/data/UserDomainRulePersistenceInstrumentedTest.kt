package io.github.xiangwang2000.dnsshield.data

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.blocking.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class UserDomainRulePersistenceInstrumentedTest {
    @Test
    fun rulesSurviveReopenAndRemovalRestoresBlocking() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("io.github.xiangwang2000.dnsshield.d07test", context.packageName)
        val name = "d07-persistence-${System.nanoTime()}.db"
        fun open() = Room.databaseBuilder(context, AppDatabase::class.java, name)
            .addMigrations(AppDatabase.MIGRATION_1_2).build()
        var db = open()
        fun matcher(rules: List<UserDomainRuleEntity>) = CompositeDomainMatcher(
            blockers = listOf(DomainMatcher { true }),
            userRules = UserDomainRuleMatcher(rules.map {
                UserDomainRule(it.domain, DomainRuleAction.valueOf(it.action), it.includeSubdomains)
            })
        )
        try {
            val allow = UserDomainRuleEntity(domain = "example.com", action = "ALLOW", includeSubdomains = false)
            db.dnsDao().replaceUserDomainRule(allow)
            var policy = matcher(db.dnsDao().getUserDomainRulesList())
            assertFalse(policy.shouldBlock("example.com"))
            assertTrue(policy.shouldBlock("cdn.example.com"))
            db.close()
            db = open()
            assertFalse(matcher(db.dnsDao().getUserDomainRulesList()).shouldBlock("example.com"))
            db.dnsDao().deleteUserDomainRule("example.com", false)
            assertTrue(matcher(db.dnsDao().getUserDomainRulesList()).shouldBlock("example.com"))

            val tree = allow.copy(includeSubdomains = true)
            db.dnsDao().replaceUserDomainRule(tree)
            policy = matcher(db.dnsDao().getUserDomainRulesList())
            assertFalse(policy.shouldBlock("cdn.example.com"))
            assertTrue(policy.shouldBlock("lookalike-example.com"))
            val exactBlock = allow.copy(action = "BLOCK")
            db.dnsDao().replaceUserDomainRule(exactBlock)
            policy = matcher(db.dnsDao().getUserDomainRulesList())
            assertTrue(policy.shouldBlock("example.com"))
            assertFalse(policy.shouldBlock("cdn.example.com"))
            val idn = requireNotNull(DomainNameNormalizer.normalize("例子.測試"))
            db.dnsDao().replaceUserDomainRule(allow.copy(domain = idn))
            assertFalse(matcher(db.dnsDao().getUserDomainRulesList()).shouldBlock("例子.測試"))

            val changed = tree.copy(action = "BLOCK", revision = "new-revision")
            db.dnsDao().replaceUserDomainRule(changed)
            assertFalse(db.dnsDao().restoreUserDomainRule(tree.domain, true, tree.revision, null))
            assertTrue(db.dnsDao().restoreUserDomainRule(tree.domain, true, changed.revision, tree))
            assertFalse(matcher(db.dnsDao().getUserDomainRulesList()).shouldBlock("cdn.example.com"))
        } finally {
            db.close()
            assertTrue(context.deleteDatabase(name))
        }
    }
}
