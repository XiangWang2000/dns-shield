package io.github.xiangwang2000.dnsshield.ui

import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.ui.Modifier
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.xiangwang2000.dnsshield.DnsShieldScreen
import io.github.xiangwang2000.dnsshield.MainActivity
import io.github.xiangwang2000.dnsshield.data.DnsServer
import io.github.xiangwang2000.dnsshield.data.UserDomainRuleEntity
import io.github.xiangwang2000.dnsshield.service.DnsDecision
import io.github.xiangwang2000.dnsshield.service.DnsDecisionEvent
import io.github.xiangwang2000.dnsshield.service.DnsDecisionReason
import io.github.xiangwang2000.dnsshield.service.UnderlyingNetworkConnectivity
import io.github.xiangwang2000.dnsshield.service.VpnLifecycleState
import io.github.xiangwang2000.dnsshield.blocking.RuleBlocklistSource
import io.github.xiangwang2000.dnsshield.blocking.RulePolicyStatus
import io.github.xiangwang2000.dnsshield.viewmodel.AppInfo
import io.github.xiangwang2000.dnsshield.viewmodel.DomainRuleUndoToken
import java.io.File
import io.github.xiangwang2000.dnsshield.ui.theme.MyApplicationTheme
import io.github.xiangwang2000.dnsshield.viewmodel.DnsShieldUiState
import kotlinx.coroutines.CompletableDeferred
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicInteger

// Test user actions through Android accessibility, independently of Compose internals.
@RunWith(AndroidJUnit4::class)
class DashboardUsabilityInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private var activity: MainActivity? = null
    private val server = DnsServer(id = 1, name = "Test resolver", primaryIp = "8.8.8.8", secondaryIp = "8.8.4.4", isActive = true)

    @After
    fun finishActivity() {
        activity?.let { current -> instrumentation.runOnMainSync { current.finish() } }
    }

    @Test
    fun customDnsSaveCannotRepeatAndFailureKeepsEnteredValues() {
        val attempts = AtomicInteger()
        val result = CompletableDeferred<String?>()
        render(onAddDns = { attempts.incrementAndGet(); result.await() })
        clickVisible("add_dns_button", "control_center_list")
        setText("dialog_dns_name_input", "My resolver")
        setText("dialog_dns_primary_input", "8.8.8.8")
        click("dialog_confirm_button")
        waitUntil { attempts.get() == 1 }
        waitUntil { !requireNode("dialog_confirm_button").isEnabled }
        assertFalse("Saving must disable duplicate submission", requireNode("dialog_confirm_button").isEnabled)
        requireNode("dialog_confirm_button").performAction(AccessibilityNodeInfo.ACTION_CLICK)
        SystemClock.sleep(100)
        assertEquals(1, attempts.get())
        result.complete("這個名稱已存在，請換一個名稱。")
        waitUntil { findNode("dialog_dns_save_error") != null }
        assertTrue(textIn(requireNode("dialog_dns_save_error")).contains("名稱已存在"))
        assertTrue(textIn(requireNode("dialog_dns_name_input")).contains("My resolver"))
        assertTrue(requireNode("dialog_confirm_button").isEnabled)
    }

    // The Boolean accessor is needed on the supported API 24-35 devices.
    @Suppress("DEPRECATION")
    @Test
    fun resolverSelectionAndFallbackHaveSeparateActions() {
        val selections = AtomicInteger()
        val fallbackChanges = AtomicInteger()
        render(onSelect = { selections.incrementAndGet() }, onFallback = { fallbackChanges.incrementAndGet() })
        clickVisible("dns_plaintext_fallback_1", "control_center_list")
        waitUntil { fallbackChanges.get() == 1 }
        assertEquals(0, selections.get())
        clickVisible("select_dns_1", "control_center_list")
        waitUntil { selections.get() == 1 }
        assertEquals(1, fallbackChanges.get())
        assertTrue("Selection must expose native radio state", requireNode("select_dns_1").let { it.isCheckable && it.isChecked })
    }

    @Test
    fun domainRuleSaveCannotRepeatAndFailureKeepsInput() {
        val attempts = AtomicInteger()
        val result = CompletableDeferred<String?>()
        render(onSaveRule = { attempts.incrementAndGet(); result.await() })
        click("tab_domain_rules")
        click("add_domain_rule_button")
        setText("domain_rule_input", "example.com")
        click("save_domain_rule_button")
        waitUntil { attempts.get() == 1 }
        waitUntil { !requireNode("save_domain_rule_button").isEnabled }
        assertFalse(requireNode("save_domain_rule_button").isEnabled)
        result.complete("規則無法儲存，請稍後再試。")
        waitUntil { requireNode("save_domain_rule_button").isEnabled }
        assertTrue(textIn(requireNode("domain_rule_input")).contains("example.com"))
        assertEquals(1, attempts.get())
    }

    @Test
    fun sharedDohEndpointIsShownOnce() {
        render()
        clickVisible("dns_endpoint_details_1", "control_center_list")
        val endpoint = "DoH：https://dns.google/dns-query"
        waitUntil { countText(endpoint) == 1 }
        assertEquals(0, countText("主要 DoH：https://dns.google/dns-query"))
        assertEquals(0, countText("備援 DoH：https://dns.google/dns-query"))
        assertEquals(1, countText("主要與備援共用同一個 DoH 服務。"))
        capture("shared-doh.png")
    }

    @Test
    fun allowingLoggedDomainUpdatesCurrentRuleAndUndoRestoresAction() {
        val domain = "ads.example.com"
        val rule = UserDomainRuleEntity(domain = domain, action = "ALLOW", includeSubdomains = false)
        val state = mutableStateOf(DnsShieldUiState(
            blockedEvents = listOf(DnsDecisionEvent(7, domain, DnsDecision.BLOCK,
                DnsDecisionReason.PROTECTION_LIST, 1_000L, recordCount = 4L))
        ))
        val attempts = AtomicInteger()
        val undos = AtomicInteger()
        render(
            state = state,
            onAllowDomain = {
                assertEquals(domain, it)
                attempts.incrementAndGet()
                state.value = state.value.copy(userDomainRules = listOf(rule))
                DomainRuleUndoToken(domain, false, rule.revision, null)
            },
            onUndoRule = {
                undos.incrementAndGet()
                state.value = state.value.copy(userDomainRules = emptyList())
                true
            }
        )
        click("tab_logs")
        assertTrue(textIn(requireNode("decision_event_summary_7")).contains("4 次"))
        capture("domain-before-allow.png")
        click("allow_blocked_7")
        waitUntil { findNode("allowed_rule_7") != null }
        assertNull(findNode("allow_blocked_7"))
        assertTrue("The historical decision must remain a block", textIn(requireNode("decision_event_7")).contains("已封鎖"))
        capture("domain-after-allow.png")
        clickText("復原")
        waitUntil { findNode("allow_blocked_7")?.isEnabled == true }
        assertNull(findNode("allowed_rule_7"))
        assertEquals(1, attempts.get())
        assertEquals(1, undos.get())
    }

    @Test
    fun loggedDomainActionsHonorParentAllowAndMoreSpecificBlock() {
        val state = mutableStateOf(DnsShieldUiState(
            blockedEvents = listOf(
                DnsDecisionEvent(7, "ads.example.com", DnsDecision.BLOCK, DnsDecisionReason.USER_RULE, 1_000L),
                DnsDecisionEvent(8, "news.example.com", DnsDecision.BLOCK, DnsDecisionReason.PROTECTION_LIST, 1_000L)
            ),
            userDomainRules = listOf(
                UserDomainRuleEntity(domain = "example.com", action = "ALLOW", includeSubdomains = true),
                UserDomainRuleEntity(domain = "ads.example.com", action = "BLOCK", includeSubdomains = false)
            )
        ))
        render(state = state)
        click("tab_logs")
        assertTrue(requireNode("allow_blocked_7").isEnabled)
        scrollVisible("allowed_rule_8", "blocked_events")
        assertNotNull(requireNode("allowed_rule_8"))
        assertNull(findNode("allow_blocked_8"))
    }

    @Test
    fun runningProtectionTracksNetworkStatusWithoutChangingToggle() {
        val state = mutableStateOf(DnsShieldUiState(
            isRunning = true,
            vpnLifecycleState = VpnLifecycleState.RUNNING
        ))
        render(state = state)
        val states = listOf(
            UnderlyingNetworkConnectivity.UNKNOWN to "確認網路中",
            UnderlyingNetworkConnectivity.OFFLINE to "等待網路",
            UnderlyingNetworkConnectivity.CONNECTING to "確認網路連線中",
            UnderlyingNetworkConnectivity.CAPTIVE_PORTAL to "網路需要登入",
            UnderlyingNetworkConnectivity.ONLINE to "DNS 防護中"
        )
        for ((network, label) in states) {
            instrumentation.runOnMainSync { state.value = state.value.copy(networkConnectivity = network) }
            try {
                waitUntil { textIn(requireNode("protection_status_label")) == label }
            } catch (failure: AssertionError) {
                throw AssertionError(
                    "Network $network expected=$label; card=${findNode("protection_status_label")?.let(::textIn)}; " +
                        "header=${findNode("protection_header_status")?.let(::textIn)}", failure
                )
            }
            assertEquals(label, textIn(requireNode("protection_header_status")))
            assertTrue(textIn(requireNode("power_button")).contains("關閉防護"))
            if (network == UnderlyingNetworkConnectivity.OFFLINE) {
                assertTrue(textIn(requireNode("protection_status_description")).contains("防護已啟用"))
                capture("network-offline.png")
            }
        }
        capture("network-online.png")
    }

    @Test
    fun blocklistSourceDateIsVisibleWithoutOpeningDetails() {
        val status = RulePolicyStatus(
            source = RuleBlocklistSource.APK_BUNDLED,
            sourceName = "badmojr/1Hosts Lite",
            entryCount = 102_241,
            sourceDate = "2026-09-03"
        )
        render(state = mutableStateOf(DnsShieldUiState(rulePolicyStatus = status)))
        scrollVisible("rule_status_card", "control_center_list")
        val summary = textIn(requireNode("rule_status_card"))
        assertTrue(summary.contains("102241"))
        assertTrue(summary.contains("來源 2026-09-03"))
        assertEquals("Source date must be in the collapsed summary", 0, countText("來源日期：2026-09-03"))
        capture("blocklist-source-date.png")
    }

    @Test
    fun blocklistWithNoSourceDateShowsUnknownRatherThanAFabricatedDate() {
        render(state = mutableStateOf(DnsShieldUiState(rulePolicyStatus = RulePolicyStatus(
            source = RuleBlocklistSource.APK_BUNDLED,
            sourceName = "Test list",
            entryCount = 10
        ))))
        scrollVisible("rule_status_card", "control_center_list")
        assertTrue(textIn(requireNode("rule_status_card")).contains("來源日期未知"))
    }

    @Test
    fun serviceAppliedDnsIsSeparateFromSelectionAndHiddenAfterStopping() {
        val selected = server.copy(name = "Saved resolver")
        val state = mutableStateOf(DnsShieldUiState(
            vpnLifecycleState = VpnLifecycleState.RUNNING,
            networkConnectivity = UnderlyingNetworkConnectivity.ONLINE,
            activeDns = "Running resolver (1.1.1.1)",
            activeDnsServer = selected,
            dnsServers = listOf(selected)
        ))
        render(state = state)
        scrollVisible("service_applied_dns", "control_center_list")
        assertTrue(textIn(requireNode("stat_active_dns")).contains("Saved resolver"))
        assertTrue(textIn(requireNode("service_applied_dns")).contains("Running resolver (1.1.1.1)"))
        capture("selected-and-applied-dns.png")
        instrumentation.runOnMainSync { state.value = state.value.copy(vpnLifecycleState = VpnLifecycleState.STOPPED) }
        waitUntil { findNode("service_applied_dns") == null }
        assertNull("A retained service value is not a running resolver after stop", findNode("service_applied_dns"))
        assertNull("Last transport should not imply an active connection after stop", findNode("dns_transport_status"))
        assertTrue(textIn(requireNode("stat_active_dns")).contains("Saved resolver"))
    }

    @Test
    fun privateBlocklistDoesNotClaimItUpdatesWithTheApp() {
        render(state = mutableStateOf(DnsShieldUiState(rulePolicyStatus = RulePolicyStatus(
            source = RuleBlocklistSource.PRIVATE_OVERRIDE,
            sourceName = "Device list",
            entryCount = 10
        ))))
        clickVisible("rule_status_card", "control_center_list")
        scrollVisible("rule_source_note", "control_center_list")
        assertEquals("目前使用裝置上的自訂名單。", textIn(requireNode("rule_source_note")))
        assertEquals(0, countText("名單隨 App 更新，不會在背景下載。"))
    }

    @Test
    fun appLoadFailureOffersRetryAndKeepsTheSearchLabel() {
        val attempts = AtomicInteger()
        val state = mutableStateOf(DnsShieldUiState(appLoadError = "無法載入 App 清單，請再試一次。"))
        render(state = state, onRetryApps = {
            attempts.incrementAndGet()
            state.value = state.value.copy(appLoadError = null, isLoadingApps = true)
        })
        click("tab_exempt")
        assertTrue(textIn(requireNode("app_load_error")).contains("無法載入 App 清單"))
        assertEquals(android.view.View.ACCESSIBILITY_LIVE_REGION_POLITE, requireNode("app_load_error").liveRegion)
        clickVisible("retry_load_apps_button", "app_exempt_list")
        waitUntil { attempts.get() == 1 && findNode("retry_load_apps_button") == null }
        assertEquals(1, attempts.get())
        instrumentation.runOnMainSync {
            state.value = state.value.copy(
                isLoadingApps = false,
                filteredApps = listOf(AppInfo("test.calendar", "Calendar", false))
            )
        }
        waitUntil { findNode("checkbox_test.calendar") != null }
        assertNull(findNode("app_load_error"))
        setText("app_search_input", "Calendar")
        assertTrue("Typed search must keep its field label", textIn(requireNode("app_search_input")).contains("搜尋 App"))
    }

    // The Boolean accessor is needed on the supported API 24-35 devices.
    @Suppress("DEPRECATION")
    @Test
    fun subdomainOptionExposesItsLabelAndToggleStateOnTheWholeRow() {
        render()
        click("tab_domain_rules")
        click("add_domain_rule_button")
        scrollVisible("domain_rule_include_subdomains", "domain_rule_dialog_scroll")
        val option = requireNode("domain_rule_include_subdomains")
        assertTrue(textIn(option).contains("包含子網域"))
        assertTrue(option.isCheckable)
        assertFalse(option.isChecked)
        click("domain_rule_include_subdomains")
        waitUntil { requireNode("domain_rule_include_subdomains").isChecked }
        assertTrue(textIn(requireNode("domain_rule_include_subdomains")).contains("包含子網域"))
        capture("subdomain-labelled-switch.png")
    }

    @Test
    fun longDomainKeepsMetadataAndAllowActionReachable() {
        val domain = "a-very-long-advertising-subdomain.with-another-long-label.for-layout-checks.example.com"
        val state = mutableStateOf(DnsShieldUiState(blockedEvents = listOf(
            DnsDecisionEvent(30, domain, DnsDecision.BLOCK, DnsDecisionReason.PROTECTION_LIST, 1_000L, recordCount = 9L)
        )))
        val rule = UserDomainRuleEntity(domain = domain, action = "ALLOW", includeSubdomains = false)
        render(state = state, onAllowDomain = {
            state.value = state.value.copy(userDomainRules = listOf(rule))
            DomainRuleUndoToken(domain, false, rule.revision, null)
        }, onUndoRule = {
            state.value = state.value.copy(userDomainRules = emptyList())
            true
        })
        click("tab_logs")
        scrollVisible("copy_domain_30", "blocked_events")
        assertTrue(requireNode("copy_domain_30").isEnabled)
        assertTrue(textIn(requireNode("domain_log_text_30")).contains(domain))
        scrollVisible("decision_event_summary_30", "blocked_events")
        val summary = textIn(requireNode("decision_event_summary_30"))
        assertTrue("Old events need a date, not only a clock time", summary.contains("1970/"))
        assertTrue("The count covers all merged records", summary.contains("累計 9 次"))
        capture("long-domain-metadata.png")
        clickVisible("allow_blocked_30", "blocked_events")
        scrollVisible("allowed_rule_30", "blocked_events")
        assertTrue(requireNode("allowed_rule_30").isVisibleToUser)
        assertNull(findNode("allow_blocked_30"))
        capture("long-domain-allowed.png")
        clickText("復原")
        waitUntil { findNode("allow_blocked_30")?.isEnabled == true }
    }

    private fun render(
        onAddDns: suspend () -> String? = { null },
        onSelect: () -> Unit = {},
        onFallback: () -> Unit = {},
        onRetryApps: () -> Unit = {},
        onSaveRule: suspend () -> String? = { null },
        state: MutableState<DnsShieldUiState>? = null,
        onAllowDomain: suspend (String) -> DomainRuleUndoToken = { error("Unused by this scenario") },
        onUndoRule: suspend (DomainRuleUndoToken) -> Boolean = { false }
    ) {
        val intent = Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        val current = instrumentation.startActivitySync(intent) as MainActivity
        activity = current
        instrumentation.runOnMainSync {
            current.setContent {
                MyApplicationTheme {
                    Scaffold(modifier = Modifier.fillMaxSize()) { padding ->
                        DnsShieldScreen(
                            uiState = state?.value ?: DnsShieldUiState(dnsServers = listOf(server), activeDnsServer = server),
                            onToggleVpn = {},
                            onSelectDns = { onSelect() },
                            onAddCustomDns = { _, _, _, _, _, _, _, _ -> onAddDns() },
                            onDeleteDns = {},
                            onSetPlaintextFallback = { _, _ -> onFallback() },
                            onSearchChange = { query -> state?.let { it.value = it.value.copy(appSearchQuery = query) } },
                            onToggleBypass = { _, _, _ -> },
                            onInfoCardDismiss = {},
                            onInfoCardRestore = {},
                            onClearLogs = {},
                            onRestartVpn = {},
                            onLoadAppsIfNeeded = {},
                            onRetryLoadApps = onRetryApps,
                            onDomainRuleSearchChange = {},
                            onSaveDomainRule = { _, _, _ -> onSaveRule() },
                            onDeleteDomainRule = {},
                            onAllowBlockedDomain = onAllowDomain,
                            onUndoDomainRule = onUndoRule,
                            modifier = Modifier.padding(padding)
                        )
                    }
                }
            }
        }
        waitUntil { findNode("tab_control") != null }
    }

    private fun capture(name: String) {
        val directory = File(instrumentation.targetContext.getExternalFilesDir(null), "ui-checks-20261029")
        check(directory.isDirectory || directory.mkdirs())
        val screenshot = requireNotNull(instrumentation.uiAutomation.takeScreenshot())
        try {
            File(directory, name).outputStream().use { assertTrue(screenshot.compress(Bitmap.CompressFormat.PNG, 100, it)) }
        } finally {
            screenshot.recycle()
        }
    }

    private fun countText(text: String): Int {
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: return 0
        fun count(node: AccessibilityNodeInfo): Int =
            (if (node.text?.toString() == text) 1 else 0) +
                (0 until node.childCount).sumOf { index -> node.getChild(index)?.let { count(it) } ?: 0 }
        return count(root)
    }

    private fun clickText(text: String) {
        fun find(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
            if (node.text?.toString() == text) {
                var target: AccessibilityNodeInfo? = node
                while (target != null && !target.isClickable) target = target.parent
                return target
            }
            for (index in 0 until node.childCount) {
                node.getChild(index)?.let { child -> find(child)?.let { return it } }
            }
            return null
        }
        waitUntil { instrumentation.uiAutomation.rootInActiveWindow?.let { find(it) } != null }
        val node = requireNotNull(instrumentation.uiAutomation.rootInActiveWindow?.let { find(it) })
        assertTrue(node.performAction(AccessibilityNodeInfo.ACTION_CLICK))
    }

    private fun setText(tag: String, value: String) {
        val arguments = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value)
        }
        assertTrue("Cannot enter text in $tag", requireNode(tag).performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, arguments))
        waitUntil { textIn(requireNode(tag)).contains(value) }
    }

    private fun click(tag: String) {
        assertTrue("Cannot click $tag", requireNode(tag).performAction(AccessibilityNodeInfo.ACTION_CLICK))
        SystemClock.sleep(150)
    }

    private fun clickVisible(tag: String, scrollTag: String) {
        scrollVisible(tag, scrollTag) { node -> node.performAction(AccessibilityNodeInfo.ACTION_CLICK) }
    }

    private fun scrollVisible(
        tag: String,
        scrollTag: String,
        onVisible: (AccessibilityNodeInfo) -> Boolean = { true }
    ) {
        val deadline = SystemClock.uptimeMillis() + 7000
        while (SystemClock.uptimeMillis() < deadline) {
            val target = findNode(tag)
            if (target?.isVisibleToUser == true) {
                if (onVisible(target)) return
            } else {
                // Accessibility scrolling is asynchronous; a rejected repeat must not reverse it.
                requireNode(scrollTag).performAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)
            }
            SystemClock.sleep(100)
        }
        dumpFailure("cannot-reach-" + tag)
        fail("Cannot reach " + tag + " in " + scrollTag)
    }

    private fun findNode(tag: String): AccessibilityNodeInfo? {
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: return null
        fun find(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
            if (node.viewIdResourceName == tag) {
                // UiAutomation can retain a pre-update snapshot after taking a screenshot.
                return node.takeIf { it.refresh() }
            }
            for (index in 0 until node.childCount) {
                node.getChild(index)?.let { find(it)?.let { found -> return found } }
            }
            return null
        }
        return find(root)
    }

    private fun requireNode(tag: String): AccessibilityNodeInfo {
        waitUntil { findNode(tag) != null }
        return findNode(tag) ?: throw AssertionError("Missing accessible UI node: $tag")
    }

    private fun textIn(node: AccessibilityNodeInfo): String = buildString {
        node.text?.let { append(it) }
        for (index in 0 until node.childCount) node.getChild(index)?.let { append(textIn(it)) }
    }

    private fun waitUntil(condition: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 7000
        while (SystemClock.uptimeMillis() < deadline) {
            if (condition()) return
            SystemClock.sleep(100)
        }
        val succeeded = condition()
        if (!succeeded) dumpFailure("timed-out-" + SystemClock.uptimeMillis())
        assertTrue("UI condition timed out", succeeded)
    }

    private fun dumpFailure(name: String) {
        val directory = File(instrumentation.targetContext.getExternalFilesDir(null), "ui-checks-20261029")
        check(directory.isDirectory || directory.mkdirs())
        val tree = buildString {
            fun visit(node: AccessibilityNodeInfo, depth: Int) {
                append("  ".repeat(depth)).append(node.viewIdResourceName).append(" | ")
                    .append(node.className).append(" | visible=").append(node.isVisibleToUser)
                    .append(" | clickable=").append(node.isClickable).append(" | text=").append(node.text).append('\n')
                for (index in 0 until node.childCount) node.getChild(index)?.let { visit(it, depth + 1) }
            }
            instrumentation.uiAutomation.rootInActiveWindow?.let { visit(it, 0) }
        }
        File(directory, name + ".txt").writeText(tree)
        capture(name + ".png")
    }
}
