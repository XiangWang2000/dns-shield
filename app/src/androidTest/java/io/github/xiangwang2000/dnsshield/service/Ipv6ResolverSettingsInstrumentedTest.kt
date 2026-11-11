package io.github.xiangwang2000.dnsshield.service

import android.app.Application
import androidx.lifecycle.ViewModelStore
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.viewmodel.DnsVpnViewModel
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Ipv6ResolverSettingsInstrumentedTest {
    @Test
    fun canonicalIpv6AndMixedBootstrapPersistAndEquivalentDuplicatesAreRejected() = runBlocking {
        val application = ApplicationProvider.getApplicationContext<Application>()
        val dao = AppDatabase.getDatabase(application).dnsDao()
        val suffix = "a" + UUID.randomUUID().toString().replace("-", "").take(3)
        val name = "IPv6 settings ${UUID.randomUUID()}"
        val duplicateName = "$name duplicate"
        val primary = "2001:db8::$suffix:53"
        val store = ViewModelStore()
        val model = withContext(Dispatchers.Main) {
            DnsVpnViewModel(application).also { store.put("ipv6-settings", it) }
        }
        try {
            assertNull(model.addCustomDnsServer(
                name = name,
                primaryIp = "2001:0DB8:0:0:0:0:$suffix:0053",
                secondaryIp = "2001:0db8:0:0:0:0:$suffix:0055",
                allowPlaintextFallback = false,
                primaryDohUrl = "https://resolver.example/dns-query",
                primaryDohBootstrapIps = "2001:0DB8:0:0:0:0:$suffix:0054,2001:db8::$suffix:54,192.0.2.53"
            ))
            val saved = dao.getDnsServersList().single { it.name == name }
            assertEquals(primary, saved.primaryIp)
            assertEquals("2001:db8::$suffix:55", saved.secondaryIp)
            assertEquals("2001:db8::$suffix:54,192.0.2.53", saved.primaryDohBootstrapIps)
            assertFalse(saved.allowPlaintextFallback)
            assertNotNull(model.addCustomDnsServer(
                name = duplicateName,
                primaryIp = primary,
                secondaryIp = null
            ))
            assertFalse(dao.getDnsServersList().any { it.name == duplicateName })
            assertNotNull(model.addCustomDnsServer(
                name = duplicateName,
                primaryIp = "fe80::1%wlan0",
                secondaryIp = null
            ))
            assertFalse(dao.getDnsServersList().any { it.name == duplicateName })
        } finally {
            dao.getDnsServersList().filter { it.name == name || it.name == duplicateName }
                .forEach { dao.deleteDnsServerById(it.id) }
            withContext(Dispatchers.Main) { store.clear() }
        }
    }
}
