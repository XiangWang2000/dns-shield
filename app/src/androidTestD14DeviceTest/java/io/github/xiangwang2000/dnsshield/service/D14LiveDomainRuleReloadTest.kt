package io.github.xiangwang2000.dnsshield.service

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.BuildConfig
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.UserDomainRuleEntity
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Exercises live user-rule reloads through the real TUN: a positive answer cached while a
 * domain is allowed must not survive the switch back to BLOCK.
 */
@RunWith(AndroidJUnit4::class)
class D14LiveDomainRuleReloadTest {
    @Test
    fun ruleReloadInvalidatesCachedAnswerThroughTun() = runBlocking {
        assertTrue("Run only the isolated .d14test target.", BuildConfig.D14_DEVICE_TEST)
        val context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        assertEquals("io.github.xiangwang2000.dnsshield.d14test", context.packageName)
        ensureD14VpnConsent(context)
        assertEquals(
            "Stop an existing D14 VPN before running this isolated lifecycle test.",
            VpnLifecycleState.STOPPED,
            DnsVpnService.lifecycleStateFlow.value
        )

        val dao = AppDatabase.getDatabase(context).dnsDao()
        val domain = "d14-rule-${System.nanoTime()}.example.com"
        assertNull("Test domain unexpectedly already has a rule", dao.getUserDomainRule(domain, false))

        val fixture = D14FakeUpstreamFixture(context)
        val upstream = fixture.upstream
        var serviceStartRequested = false
        var ruleInserted = false
        var testFailure: Throwable? = null

        try {
            fixture.install()

            ruleInserted = true
            dao.replaceUserDomainRule(
                UserDomainRuleEntity(domain = domain, action = "BLOCK", includeSubdomains = false)
            )

            serviceStartRequested = true
            ContextCompat.startForegroundService(
                context,
                Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
            )
            d14WaitForLifecycle(VpnLifecycleState.RUNNING, 20_000L)

            assertEquals(3, d14ResponseCode(d14AwaitRcode(domain, 3)))
            assertEquals("A blocked query must not reach the fake upstream.", 0, upstream.count(domain))

            dao.replaceUserDomainRule(
                UserDomainRuleEntity(domain = domain, action = "ALLOW", includeSubdomains = false)
            )
            context.startService(reloadIntent(context))
            d14AssertDnsAnswer(d14AwaitRcode(domain, 0))
            assertTrue("The allowed query must reach the fake upstream.", upstream.waitForCount(domain, 1, 2_000L))

            d14AssertDnsAnswer(d14AwaitRcode(domain, 0))
            assertEquals("A repeated allowed query must use its cache entry.", 1, upstream.count(domain))

            dao.replaceUserDomainRule(
                UserDomainRuleEntity(domain = domain, action = "BLOCK", includeSubdomains = false)
            )
            context.startService(reloadIntent(context))
            assertEquals(3, d14ResponseCode(d14AwaitRcode(domain, 3)))
            assertEquals(
                "A cached positive answer must not survive the BLOCK reload.",
                1,
                upstream.count(domain)
            )
            assertNull("Fake upstream thread failed.", upstream.failure)
        } catch (failure: Throwable) {
            testFailure = failure
            throw failure
        } finally {
            fixture.cleanup(serviceStartRequested, testFailure) {
                if (ruleInserted) dao.deleteUserDomainRule(domain, false)
            }
        }
    }

    private fun reloadIntent(context: Context) =
        Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_RELOAD_DOMAIN_POLICY)
}
