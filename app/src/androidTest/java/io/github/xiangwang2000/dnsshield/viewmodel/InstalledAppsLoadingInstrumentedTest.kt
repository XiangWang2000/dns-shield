package io.github.xiangwang2000.dnsshield.viewmodel

import android.app.Application
import androidx.lifecycle.ViewModelStore
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.data.AppDatabase
import io.github.xiangwang2000.dnsshield.data.BypassedApp
import io.github.xiangwang2000.dnsshield.service.DnsVpnService
import io.github.xiangwang2000.dnsshield.service.VpnLifecycleState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicInteger

@RunWith(AndroidJUnit4::class)
class InstalledAppsLoadingInstrumentedTest {
    @Test
    fun appListRefreshesWhenExemptionsTabIsReopened() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val application = instrumentation.targetContext.applicationContext as Application
        val store = ViewModelStore()
        val viewModel = DnsVpnViewModel(application)
        instrumentation.runOnMainSync { store.put("installed-apps", viewModel) }

        val dao = AppDatabase.getDatabase(application).dnsDao()
        val packageName = application.packageName
        val previousExclusion = dao.getBypassedAppsList().find { it.packageName == packageName }
        val attempts = AtomicInteger()
        val secondStarted = CompletableDeferred<Unit>()
        val finishSecond = CompletableDeferred<Unit>()
        viewModel.installedAppsLoader = {
            val load = attempts.incrementAndGet()
            if (load == 2) {
                secondStarted.complete(Unit)
                finishSecond.await()
            }
            listOf(AppInfo(packageName, "Example $load", isBypassed = false))
        }

        try {
            dao.deleteBypassedAppByPackage(packageName)
            viewModel.refreshInstalledAppsIfNeeded()
            val firstLoad = withTimeout(5_000) {
                viewModel.uiState.first {
                    !it.isLoadingApps && it.filteredApps.singleOrNull()?.appName == "Example 1"
                }
            }
            assertEquals("Example 1", firstLoad.filteredApps.single().appName)

            viewModel.refreshInstalledAppsIfNeeded()
            withTimeout(5_000) { secondStarted.await() }
            dao.insertBypassedApp(BypassedApp(packageName, "Test exclusion"))
            withTimeout(5_000) {
                viewModel.uiState.first { it.filteredApps.singleOrNull()?.isBypassed == true }
            }
            finishSecond.complete(Unit)

            val secondLoad = withTimeout(5_000) {
                viewModel.uiState.first {
                    !it.isLoadingApps && it.filteredApps.singleOrNull()?.appName == "Example 2"
                }
            }
            assertEquals(AppInfo(packageName, "Example 2", isBypassed = true), secondLoad.filteredApps.single())
            assertEquals(2, attempts.get())
        } finally {
            finishSecond.cancel()
            instrumentation.runOnMainSync { store.clear() }
            if (previousExclusion == null) {
                dao.deleteBypassedAppByPackage(packageName)
            } else {
                dao.insertBypassedApp(previousExclusion)
            }
        }
    }

    @Test
    fun showsUnappliedExclusionAfterFailureWithoutOpeningTab() = runBlocking<Unit> {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val application = instrumentation.targetContext.applicationContext as Application
        val dnsDao = AppDatabase.getDatabase(application).dnsDao()
        val packageName = application.packageName
        val previousExclusion = dnsDao.getBypassedAppsList().find { it.packageName == packageName }
        val previousLifecycle = DnsVpnService.lifecycleStateFlow.value
        val store = ViewModelStore()

        try {
            dnsDao.insertBypassedApp(BypassedApp(packageName, "Test exclusion"))
            DnsVpnService.lifecycleStateFlow.value = VpnLifecycleState.FAILED
            val viewModel = DnsVpnViewModel(application)
            instrumentation.runOnMainSync { store.put("unapplied-exclusion", viewModel) }

            val failed = withTimeout(5_000) {
                viewModel.uiState.first {
                    it.vpnLifecycleState == VpnLifecycleState.FAILED && it.vpnSettingsModified
                }
            }
            assertEquals(emptyList<AppInfo>(), failed.filteredApps)

            DnsVpnService.lifecycleStateFlow.value = VpnLifecycleState.STOPPED
            withTimeout(5_000) {
                viewModel.uiState.first {
                    it.vpnLifecycleState == VpnLifecycleState.STOPPED && !it.vpnSettingsModified
                }
            }
        } finally {
            instrumentation.runOnMainSync { store.clear() }
            DnsVpnService.lifecycleStateFlow.value = previousLifecycle
            if (previousExclusion == null) {
                dnsDao.deleteBypassedAppByPackage(packageName)
            } else {
                dnsDao.insertBypassedApp(previousExclusion)
            }
        }
    }

    @Test
    fun failedLoadCanRetryAndDuplicatePendingRequestIsIgnored() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val application = instrumentation.targetContext.applicationContext as Application
        val store = ViewModelStore()
        val viewModel = DnsVpnViewModel(application)
        instrumentation.runOnMainSync { store.put("installed-apps", viewModel) }

        val attempts = AtomicInteger()
        val firstStarted = CompletableDeferred<Unit>()
        val firstFailureRelease = CompletableDeferred<Unit>()
        val retryStarted = CompletableDeferred<Unit>()
        val retryResult = CompletableDeferred<List<AppInfo>>()
        viewModel.installedAppsLoader = {
            when (attempts.incrementAndGet()) {
                1 -> {
                    firstStarted.complete(Unit)
                    firstFailureRelease.await()
                    throw IllegalStateException("injected app-list failure")
                }
                2 -> {
                    retryStarted.complete(Unit)
                    retryResult.await()
                }
                else -> error("Unexpected duplicate app-list request")
            }
        }

        try {
            viewModel.refreshInstalledAppsIfNeeded()
            withTimeout(5_000) { firstStarted.await() }
            viewModel.refreshInstalledAppsIfNeeded()
            assertEquals(1, attempts.get())
            firstFailureRelease.complete(Unit)

            val failure = withTimeout(5_000) {
                viewModel.uiState.first { it.appLoadError != null && !it.isLoadingApps }
            }
            assertFalse(failure.isLoadingApps)
            assertEquals("無法載入 App 清單，請再試一次。", failure.appLoadError)
            assertEquals(1, attempts.get())

            viewModel.refreshInstalledAppsIfNeeded()
            val retryLoading = withTimeout(5_000) {
                viewModel.uiState.first { it.isLoadingApps }
            }
            assertNull(retryLoading.appLoadError)
            withTimeout(5_000) { retryStarted.await() }
            viewModel.refreshInstalledAppsIfNeeded()
            assertEquals(2, attempts.get())

            val expectedApps = listOf(AppInfo("example.app", "Example", false))
            retryResult.complete(expectedApps)
            val success = withTimeout(5_000) {
                viewModel.uiState.first {
                    !it.isLoadingApps && it.appLoadError == null && it.filteredApps == expectedApps
                }
            }
            assertNull(success.appLoadError)
            assertEquals(expectedApps, success.filteredApps)
            assertEquals(2, attempts.get())
        } finally {
            firstFailureRelease.cancel()
            retryResult.cancel()
            instrumentation.runOnMainSync { store.clear() }
        }
    }
}
