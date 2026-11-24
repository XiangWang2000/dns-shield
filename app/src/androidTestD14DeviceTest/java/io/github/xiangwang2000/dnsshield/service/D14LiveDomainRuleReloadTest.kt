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

        val dao = AppDatabase.getDatabase(context).dnsDao()
        val domain = "d14-rule-${System.nanoTime()}.example.com"
        assertNull("Test domain unexpectedly already has a rule", dao.getUserDomainRule(domain, false))

        val upstream = FakeDnsUpstream()
        val preferences = context.getSharedPreferences(DnsVpnService.D14_TEST_PREFS_NAME, Context.MODE_PRIVATE)
        val oldHost = preferences.getString(DnsVpnService.D14_TEST_UPSTREAM_HOST_KEY, null)
        val hadPort = preferences.contains(DnsVpnService.D14_TEST_UPSTREAM_PORT_KEY)
        val oldPort = preferences.getInt(DnsVpnService.D14_TEST_UPSTREAM_PORT_KEY, -1)
        val preferencesPersisted = preferences.edit()
            .putString(DnsVpnService.D14_TEST_UPSTREAM_HOST_KEY, "127.0.0.1")
            .putInt(DnsVpnService.D14_TEST_UPSTREAM_PORT_KEY, upstream.port)
            .commit()
        if (!preferencesPersisted) {
            upstream.close()
            throw AssertionError("Could not persist the loopback-only fake upstream settings.")
        }

        var serviceStartRequested = false
        var ruleInserted = false
        try {
            dao.replaceUserDomainRule(UserDomainRuleEntity(domain = domain, action = "BLOCK", includeSubdomains = false))
            ruleInserted = true

            serviceStartRequested = true
            ContextCompat.startForegroundService(
                context,
                Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_START)
            )
            d14WaitForLifecycle(VpnLifecycleState.RUNNING, 20_000L)

            assertEquals(3, d14ResponseCode(d14AwaitRcode(domain, 3)))
            assertEquals("A blocked query must not reach the fake upstream.", 0, upstream.count(domain))

            dao.replaceUserDomainRule(UserDomainRuleEntity(domain = domain, action = "ALLOW", includeSubdomains = false))
            context.startService(reloadIntent(context))
            d14AssertDnsAnswer(d14AwaitRcode(domain, 0))
            assertTrue("The allowed query must reach the fake upstream.", upstream.waitForCount(domain, 1, 2_000L))

            d14AssertDnsAnswer(d14AwaitRcode(domain, 0))
            assertEquals("A repeated allowed query must use its cache entry.", 1, upstream.count(domain))

            dao.replaceUserDomainRule(UserDomainRuleEntity(domain = domain, action = "BLOCK", includeSubdomains = false))
            context.startService(reloadIntent(context))
            assertEquals(3, d14ResponseCode(d14AwaitRcode(domain, 3)))
            assertEquals(
                "A cached positive answer must not survive the BLOCK reload.",
                1,
                upstream.count(domain)
            )
            assertNull("Fake upstream thread failed.", upstream.failure)
        } finally {
            if (serviceStartRequested) {
                context.startService(Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
                runCatching { d14WaitForLifecycle(VpnLifecycleState.STOPPED, 10_000L) }
            }
            upstream.close()
            if (DnsVpnService.lifecycleStateFlow.value == VpnLifecycleState.STOPPED) {
                preferences.edit().apply {
                    if (oldHost == null) remove(DnsVpnService.D14_TEST_UPSTREAM_HOST_KEY)
                    else putString(DnsVpnService.D14_TEST_UPSTREAM_HOST_KEY, oldHost)
                    if (hadPort) putInt(DnsVpnService.D14_TEST_UPSTREAM_PORT_KEY, oldPort)
                    else remove(DnsVpnService.D14_TEST_UPSTREAM_PORT_KEY)
                }.commit()
            }
            if (ruleInserted) dao.deleteUserDomainRule(domain, false)
        }
    }

    private fun reloadIntent(context: Context) =
        Intent(context, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_RELOAD_DOMAIN_POLICY)
}
