package io.github.xiangwang2000.dnsshield.viewmodel

import android.app.Application
import androidx.lifecycle.ViewModelStore
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.data.DnsServer
import io.github.xiangwang2000.dnsshield.service.DnsVpnService
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Collections

@RunWith(AndroidJUnit4::class)
class ResolverCommandViewModelFailureInstrumentedTest {
    private lateinit var viewModel: DnsVpnViewModel
    private lateinit var waiterScope: CoroutineScope
    private val viewModelStore = ViewModelStore()
    private val waiterFailures = Collections.synchronizedList(mutableListOf<Throwable>())

    @Before
    fun setUp() {
        DnsVpnService.setUiForeground(true)
        DnsVpnService.clearLogs()
        waiterScope = CoroutineScope(
            SupervisorJob() + Dispatchers.IO + CoroutineExceptionHandler { _, failure ->
                waiterFailures += failure
            }
        )
        val application = InstrumentationRegistry.getInstrumentation()
            .targetContext.applicationContext as Application
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            viewModel = DnsVpnViewModel(application)
            viewModelStore.put("resolver-failure-test", viewModel)
            viewModel.resolverCommandWaiterScope = waiterScope
        }
    }

    @After
    fun tearDown() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync { viewModelStore.clear() }
        waiterScope.cancel()
        DnsVpnService.clearLogs()
        DnsVpnService.setUiForeground(false)
    }

    @Test
    fun daoFailuresFromAllThreeEntrancesBecomeVisibleRecoveryLogs() = runBlocking {
        val server = server(9301)
        viewModel.resolverCommandOperations = operations(
            setActive = { throw IllegalStateException("select DAO failure") },
            updateFallback = { _, _ -> throw IllegalStateException("fallback DAO failure") },
            deleteSafely = { throw IllegalStateException("delete DAO failure") },
            dispatch = { _, _ -> error("dispatch must not run after a DAO failure") }
        )

        viewModel.selectDnsServer(server.id)
        viewModel.setPlaintextFallback(server, allow = true)
        viewModel.deleteDnsServer(server)

        awaitLogsOrFailures(listOf("DNS 切換失敗", "DNS 傳輸政策沒有儲存", "刪除 DNS 設定沒有完成"))
        val logs = viewModel.liveLogs.value
        assertTrue(logs.any { it.contains("DNS 切換失敗") })
        assertTrue(logs.any { it.contains("DNS 傳輸政策沒有儲存") })
        assertTrue(logs.any { it.contains("本次未啟用明文備援") })
        assertTrue(logs.any { it.contains("刪除 DNS 設定沒有完成") })
        assertEquals(emptyList<Throwable>(), waiterFailures.toList())
    }

    @Test
    fun dispatchFailuresAfterCommitKeepSavedRowsAndBecomeVisibleRecoveryLogs() = runBlocking {
        val server = server(9302)
        val committed = Collections.synchronizedSet(mutableSetOf<String>())
        viewModel.resolverCommandOperations = operations(
            setActive = {
                committed += "select"
                true
            },
            updateFallback = { _, _ ->
                committed += "fallback"
                1
            },
            deleteSafely = {
                committed += "delete"
                true
            },
            dispatch = { _, _ -> throw IllegalStateException("service dispatch failure") }
        )

        viewModel.selectDnsServer(server.id)
        awaitLogOrFailure("DNS 切換已儲存", 1)
        viewModel.setPlaintextFallback(server, allow = true)
        awaitLogOrFailure("DNS 傳輸政策已儲存", 2)
        viewModel.deleteDnsServer(server)
        awaitLogOrFailure("DNS 設定已刪除", 3)

        val logs = viewModel.liveLogs.value
        assertTrue(logs.any { it.contains("DNS 切換已儲存") })
        assertTrue(logs.any { it.contains("DNS 傳輸政策已儲存") })
        assertTrue(logs.any { it.contains("本次未啟用明文備援") })
        assertTrue(logs.any { it.contains("DNS 設定已刪除") })
        assertEquals(setOf("select", "fallback", "delete"), committed.toSet())
        assertEquals(emptyList<Throwable>(), waiterFailures.toList())
    }

    private suspend fun awaitLogOrFailure(message: String, expectedFailures: Int) {
        withTimeout(10_000) {
            while (
                waiterFailures.size < expectedFailures &&
                viewModel.liveLogs.value.none { it.contains(message) }
            ) {
                delay(10)
            }
        }
    }
    private suspend fun awaitLogsOrFailures(expectedMessages: List<String>) {
        withTimeout(10_000) {
            while (
                waiterFailures.size < expectedMessages.size &&
                !expectedMessages.all { expected ->
                    viewModel.liveLogs.value.any { log -> log.contains(expected) }
                }
            ) {
                delay(10)
            }
        }
    }

    private fun operations(
        setActive: suspend (Int) -> Boolean,
        updateFallback: suspend (Int, Boolean) -> Int,
        deleteSafely: suspend (Int) -> Boolean,
        dispatch: (DnsServer, Long) -> Unit
    ) = ResolverCommandOperations(
        setActiveDnsServer = setActive,
        getActiveDnsServer = { server(9300) },
        updatePlaintextFallback = updateFallback,
        deleteDnsServerSafely = deleteSafely,
        dispatch = dispatch
    )

    private fun server(id: Int) = DnsServer(
        id = id,
        name = "Test DNS",
        primaryIp = "192.0.2.1",
        secondaryIp = null,
        allowPlaintextFallback = true
    )
}
