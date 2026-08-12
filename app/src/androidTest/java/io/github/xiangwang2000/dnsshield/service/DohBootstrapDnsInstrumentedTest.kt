package io.github.xiangwang2000.dnsshield.service

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertSame
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DohBootstrapDnsInstrumentedTest {
    @Test
    fun serviceHttpClientUsesNonRecursiveDohBootstrapDns() {
        val client = DnsVpnService.getOkHttpClient()
        assertSame(DohBootstrapDns, client.dns)
        assertEquals(24, client.dispatcher.maxRequestsPerHost)
    }
}
